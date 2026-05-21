package com.cinetrack.profile;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Chapter 15: Exposes the authenticated user's profile as JSON.
 *
 * @AuthenticationPrincipal injects whatever OAuth2User was stored in the
 * SecurityContext after the login flow completed: in this chapter that's
 * the enriched CineTrack principal produced by SocialUserService.
 */
@RestController
@RequestMapping("/api")
public class ProfileController {

    @GetMapping("/me")
    public Map<String, Object> me(@AuthenticationPrincipal OAuth2User principal) {
        return Map.of(
                "name", principal.getAttribute("name") != null
                        ? principal.getAttribute("name") : principal.getName(),
                "email", principal.getName(),
                "subscription_tier", principal.getAttribute("subscription_tier") != null
                        ? principal.getAttribute("subscription_tier") : "STANDARD"
        );
    }
}
