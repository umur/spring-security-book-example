package com.cinetrack.subscription;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Subscription tier upgrade endpoint requiring multi-factor proof.
 *
 * Changing a subscription tier is a sensitive mutation — one compromised
 * password should not be enough. The {@code FACTOR_TOTP} authority is added
 * to the security context only after a successful TOTP step-up challenge.
 *
 * The access rule ({@code hasAuthority("FACTOR_TOTP")}) lives in
 * {@link com.cinetrack.security.SecurityConfig}. The {@link FactorAuthTest}
 * shows how to assert on it using the {@code jwt()} post-processor with
 * explicit authority lists.
 */
@RestController
@RequestMapping("/api/subscriptions")
public class SubscriptionController {

    @PutMapping("/tier")
    public ResponseEntity<TierResponse> upgradeTier(@RequestBody TierRequest request) {
        return ResponseEntity.ok(new TierResponse(request.tier(), "Subscription updated"));
    }
}
