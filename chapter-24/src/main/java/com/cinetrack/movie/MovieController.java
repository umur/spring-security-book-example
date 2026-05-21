package com.cinetrack.movie;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Movie listing endpoint: authenticated users only (see SecurityConfig).
 *
 * Every successful request here is preceded by a successful authentication
 * event that {@link com.cinetrack.security.SecurityAuditListener} captures
 * and counts. Every failed attempt to reach this endpoint without credentials
 * fires an authentication failure event.
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
