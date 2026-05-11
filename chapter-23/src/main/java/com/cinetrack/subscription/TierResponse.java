package com.cinetrack.subscription;

/**
 * Response returned after a successful subscription tier change.
 */
public record TierResponse(String tier, String message) {
}
