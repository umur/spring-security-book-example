package com.cinetrack.subscription;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Manages subscription tier changes.
 *
 * {@code PUT /api/subscriptions/tier} is a sensitive billing mutation, so the
 * security configuration requires the {@code FACTOR_TOTP} authority — meaning
 * the user must have completed a TOTP step-up challenge before this request is
 * accepted. The controller itself is unaware of this requirement; the filter
 * chain enforces it before the request reaches this method.
 */
@RestController
@RequestMapping("/api/subscriptions")
public class SubscriptionController {

    @PutMapping("/tier")
    public ResponseEntity<Map<String, String>> changeTier(@RequestParam String tier) {
        return ResponseEntity.ok(Map.of("status", "updated", "tier", tier));
    }
}
