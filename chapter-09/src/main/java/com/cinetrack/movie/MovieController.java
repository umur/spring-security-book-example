package com.cinetrack.movie;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Catalog endpoint. Requires authentication — enforced by the SecurityFilterChain.
 * Unauthenticated requests are redirected to the SAML2 IdP for SP-initiated SSO.
 */
@RestController
@RequestMapping("/api/movies")
public class MovieController {

    @GetMapping
    public List<Movie> list() {
        return List.of(
                new Movie(1L, "Inception", 2010),
                new Movie(2L, "Interstellar", 2014),
                new Movie(3L, "The Dark Knight", 2008)
        );
    }
}
