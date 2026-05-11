package com.cinetrack.movie;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Optional;

/**
 * Movie endpoints accessible to {@code ROLE_USER} and {@code ROLE_ADMIN} via
 * HTTP Basic, or to JWT callers via Bearer token (see SecurityConfig for rules).
 *
 * The {@code tier} claim extraction on the detail endpoint demonstrates that
 * JWT claims beyond {@code sub} are available to the controller — a common
 * pattern for carrying subscription tier, tenant ID, or feature flags in the
 * token body.
 */
@RestController
@RequestMapping("/api/movies")
public class MovieController {

    private static final List<Movie> MOVIES = List.of(
            new Movie(1L, "Inception", 2010),
            new Movie(2L, "Interstellar", 2014),
            new Movie(3L, "The Dark Knight", 2008),
            new Movie(4L, "Parasite", 2019)
    );

    @GetMapping
    public List<Movie> list() {
        return MOVIES;
    }

    /**
     * Detail endpoint that reads an optional {@code tier} claim from the JWT.
     * When called via HTTP Basic the principal is a {@code UserDetails}, not a
     * {@code Jwt}, so the parameter is nullable.
     */
    @GetMapping("/{id}")
    public Movie detail(@PathVariable Long id,
                        @AuthenticationPrincipal(errorOnInvalidType = false) Jwt jwt) {
        if (jwt != null) {
            String tier = jwt.getClaimAsString("tier");
            if (tier != null) {
                // In a real application: apply tier-based content filtering here
            }
        }
        return MOVIES.stream()
                .filter(m -> m.id().equals(id))
                .findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }
}
