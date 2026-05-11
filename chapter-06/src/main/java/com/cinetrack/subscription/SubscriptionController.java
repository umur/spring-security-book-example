package com.cinetrack.subscription;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

/**
 * Handles subscription tier changes.
 *
 * The upgrade endpoint is protected by the FACTOR_TOTP authority, meaning the
 * caller must have completed both password authentication and TOTP verification
 * before the request is admitted. This mirrors the "step-up authentication"
 * pattern used by financial applications for high-value actions.
 */
@RestController
@RequestMapping("/api/subscriptions")
public class SubscriptionController {

    @PutMapping("/upgrade")
    public ResponseEntity<Map<String, String>> upgrade(Principal principal) {
        return ResponseEntity.ok(Map.of(
                "username", principal.getName(),
                "tier", "PREMIUM",
                "message", "Subscription upgraded successfully"
        ));
    }
}
