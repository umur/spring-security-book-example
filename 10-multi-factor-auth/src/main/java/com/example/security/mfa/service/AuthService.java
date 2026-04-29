package com.example.security.mfa.service;

import com.example.security.mfa.repository.AppUserRepository;
import com.example.security.mfa.security.MfaAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final MfaService mfaService;
    private final AppUserRepository userRepository;

    // In-memory pending MFA sessions: tempToken -> username
    // In production this would be a short-lived cache (Redis, etc.)
    private final ConcurrentHashMap<String, String> pendingMfaSessions = new ConcurrentHashMap<>();

    // Fully authenticated sessions: sessionToken -> Authentication
    private final ConcurrentHashMap<String, Authentication> fullyAuthenticatedSessions = new ConcurrentHashMap<>();

    public record LoginResult(boolean mfaRequired, String tempToken, String sessionToken, String username) {}

    public LoginResult login(String username, String password) {
        Authentication auth;
        try {
            auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
        } catch (AuthenticationException ex) {
            throw new BadCredentialsException("Invalid username or password");
        }

        if (mfaService.isMfaEnabled(username)) {
            String tempToken = "tmp-" + UUID.randomUUID();
            pendingMfaSessions.put(tempToken, username);
            return new LoginResult(true, tempToken, null, username);
        }

        String sessionToken = "sess-" + UUID.randomUUID();
        fullyAuthenticatedSessions.put(sessionToken, auth);
        return new LoginResult(false, null, sessionToken, username);
    }

    public String verifyMfa(String tempToken, int totpCode) {
        String username = pendingMfaSessions.get(tempToken);
        if (username == null) {
            throw new BadCredentialsException("Invalid or expired temporary token");
        }

        if (!mfaService.verifyTotp(username, totpCode)) {
            throw new BadCredentialsException("Invalid TOTP code");
        }

        pendingMfaSessions.remove(tempToken);

        var user = userRepository.findByUsername(username)
                .orElseThrow(() -> new BadCredentialsException("User not found"));

        var fullyAuth = MfaAuthenticationToken.authenticated(
                username,
                org.springframework.security.core.authority.AuthorityUtils
                        .createAuthorityList("ROLE_" + user.getRole())
        );

        String sessionToken = "sess-" + UUID.randomUUID();
        fullyAuthenticatedSessions.put(sessionToken, fullyAuth);
        return sessionToken;
    }

    public Authentication resolveSession(String sessionToken) {
        return fullyAuthenticatedSessions.get(sessionToken);
    }
}
