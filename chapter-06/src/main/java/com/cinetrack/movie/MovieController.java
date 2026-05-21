package com.cinetrack.movie;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Exposes the stub movie catalog.
 *
 * Accessible to any user who has completed password authentication
 * (FACTOR_PASSWORD authority). TOTP is not required here.
 */
@RestController
@RequestMapping("/api/movies")
public class MovieController {

    private static final List<Movie> CATALOG = List.of(
            new Movie(1L, "Inception", "Science Fiction"),
            new Movie(2L, "Parasite", "Thriller"),
            new Movie(3L, "Interstellar", "Science Fiction")
    );

    @GetMapping
    public List<Movie> list() {
        return CATALOG;
    }
}
