package com.cinetrack.admin;

/**
 * Lightweight projection of a CineTrack user, returned by admin endpoints.
 */
public record UserSummary(String username, String role) {
}
