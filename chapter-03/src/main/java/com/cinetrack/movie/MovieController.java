package com.cinetrack.movie;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Catalog endpoint. Requires the {@code catalog:read} scope in the bearer token.
 * Authorization is enforced in SecurityConfig via scope-based rules — not here.
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
