package com.cinetrack.security;

/**
 * Domain-specific principal carrying the user's identity and subscription tier.
 *
 * In production this would be fetched from the user-service and stored on the
 * authentication object after login. In tests it is injected directly via
 * {@link WithCineTrackUser} / {@code WithCineTrackUserSecurityContextFactory},
 * making it possible to assert on business-level principal attributes without
 * a database or HTTP session.
 */
public record CineTrackPrincipal(String userId, String email, String subscriptionTier) {
}
