package com.cinetrack.admin;

/**
 * Minimal user summary returned by the admin API.
 */
public record UserSummary(String username, String subscriptionTier) {
}
