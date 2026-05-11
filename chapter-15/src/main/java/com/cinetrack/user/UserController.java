package com.cinetrack.user;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Exposes the authenticated OIDC principal as CineTrack-shaped JSON.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    // Returns the full CineTrackUser projection from OIDC ID token claims.
    @GetMapping("/me")
    public CineTrackUser me(@AuthenticationPrincipal OidcUser oidcUser) {
        return new CineTrackUser(
                oidcUser.getSubject(),
                oidcUser.getEmail(),
                oidcUser.getFullName(),
                "oidc",
                oidcUser.getPicture()
        );
    }

    // Returns a lightweight name/email summary.
    @GetMapping("/profile")
    public Map<String, String> profile(@AuthenticationPrincipal OidcUser oidcUser) {
        return Map.of(
                "name", oidcUser.getFullName() != null ? oidcUser.getFullName() : "",
                "email", oidcUser.getEmail() != null ? oidcUser.getEmail() : ""
        );
    }
}
