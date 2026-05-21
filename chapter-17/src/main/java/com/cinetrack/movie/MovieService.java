package com.cinetrack.movie;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

/**
 * Demonstrates {@code @PreAuthorize} with a compound SpEL expression that
 * mixes authority checks with parameter inspection.
 *
 * The expression {@code hasAuthority('TIER_PREMIUM') or !#movie.premiumOnly()}
 * short-circuits: premium users pass immediately; non-premium users pass only
 * when the movie itself is not restricted.
 */
@Service
public class MovieService {

    /**
     * Returns the movie if the caller holds TIER_PREMIUM, or if the movie is
     * not premium-only. Throws {@code AccessDeniedException} otherwise: before
     * this method body runs.
     */
    @PreAuthorize("hasAuthority('TIER_PREMIUM') or !#movie.premiumOnly()")
    public Movie getMovie(Movie movie) {
        return movie;
    }
}
