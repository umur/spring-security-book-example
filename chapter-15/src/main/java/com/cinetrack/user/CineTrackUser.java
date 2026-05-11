package com.cinetrack.user;

/**
 * Immutable projection of an OIDC principal into a CineTrack user.
 */
public record CineTrackUser(
        String id,
        String email,
        String name,
        String provider,
        String pictureUrl
) {
}
