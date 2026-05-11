package com.cinetrack.mfa;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Handles TOTP setup and verification for the MFA flow.
 *
 * Flow:
 *   1. User logs in with password -> SecurityConfig's success handler grants
 *      FACTOR_PASSWORD and redirects to /api/mfa/challenge if user has TOTP.
 *   2. Client calls POST /api/mfa/verify with the 6-digit code.
 *   3. If the code is valid, FACTOR_TOTP is added to the SecurityContext and
 *      the updated context is persisted back to the session.
 */
@RestController
@RequestMapping("/api/mfa")
public class MfaController {

    private final TotpService totpService;
    private final MfaUserDetailsService userDetailsService;

    public MfaController(TotpService totpService, MfaUserDetailsService userDetailsService) {
        this.totpService = totpService;
        this.userDetailsService = userDetailsService;
    }

    /**
     * Returns the TOTP shared secret and otpauth:// URI for QR-code display.
     * In production the secret is fetched from encrypted storage; here we
     * return the stub secret stored on the MfaUser record.
     */
    @GetMapping("/setup")
    public ResponseEntity<Map<String, String>> setup(Principal principal) {
        MfaUser mfaUser = userDetailsService.findMfaUser(principal.getName());
        String secret = mfaUser.totpSecret() != null
                ? mfaUser.totpSecret()
                : totpService.generateSecret();

        String otpauthUri = "otpauth://totp/CineTrack:" + principal.getName()
                + "?secret=" + secret
                + "&issuer=CineTrack"
                + "&algorithm=SHA1"
                + "&digits=6"
                + "&period=30";

        return ResponseEntity.ok(Map.of(
                "secret", secret,
                "otpauthUri", otpauthUri
        ));
    }

    /**
     * Validates the submitted TOTP code.  On success, FACTOR_TOTP is added to
     * the current authentication and the SecurityContext is re-saved to the
     * session so subsequent requests within the same session inherit it.
     */
    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verify(
            @RequestBody Map<String, String> body,
            HttpServletRequest request) {

        String code = body.get("code");
        Authentication current = SecurityContextHolder.getContext().getAuthentication();

        if (current == null || !current.isAuthenticated()) {
            return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        }

        MfaUser mfaUser = userDetailsService.findMfaUser(current.getName());
        if (mfaUser.totpSecret() == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "User has no TOTP secret"));
        }

        if (!totpService.isValid(mfaUser.totpSecret(), code)) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid TOTP code"));
        }

        // Promote the authentication by adding FACTOR_TOTP to the authority set.
        List<GrantedAuthority> upgraded = new ArrayList<>(current.getAuthorities());
        upgraded.add(new SimpleGrantedAuthority("FACTOR_TOTP"));

        Authentication upgraded_auth = UsernamePasswordAuthenticationToken.authenticated(
                current.getPrincipal(),
                current.getCredentials(),
                upgraded
        );

        SecurityContext context = SecurityContextHolder.getContext();
        context.setAuthentication(upgraded_auth);

        // Persist the upgraded context back to the session.
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.setAttribute(
                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                    context
            );
        }

        return ResponseEntity.ok(Map.of("mfaComplete", true));
    }
}
