package com.cinetrack.security;

/**
 * Domain-specific principal carrying user data beyond what Spring Security's
 * {@link org.springframework.security.core.userdetails.UserDetails} exposes.
 *
 * In production this would be populated from the user-service after login.
 * In tests it is injected via {@link WithCineTrackUser} and
 * {@link WithCineTrackUserSecurityContextFactory} so controllers can be tested
 * with a concrete principal without a database or HTTP session.
 *
 * @deprecated Use {@link CineTrackPrincipal}: retained for backward compatibility
 *             with earlier chapter examples.
 */
public record CineTrackUserPrincipal(String username, String subscriptionTier) {
}
