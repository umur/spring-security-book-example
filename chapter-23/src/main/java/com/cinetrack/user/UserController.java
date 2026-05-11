package com.cinetrack.user;

import com.cinetrack.security.CineTrackPrincipal;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * User API — returns authenticated user's details from the resolved principal.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/me")
    public Map<String, String> me(@AuthenticationPrincipal CineTrackPrincipal principal) {
        return Map.of(
                "userId", principal.userId(),
                "email", principal.email(),
                "subscriptionTier", principal.subscriptionTier()
        );
    }
}
