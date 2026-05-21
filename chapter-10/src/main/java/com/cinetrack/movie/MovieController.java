package com.cinetrack.movie;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Catalog endpoint protected by scope.
 *
 * The @PreAuthorize annotation makes the scope requirement explicit in the
 * controller itself. The SecurityConfig adds a belt-and-suspenders check at
 * the URL level: both have to pass for a request to succeed.
 *
 * SCOPE_catalog:read is the authority Spring Security produces when it finds
 * "catalog:read" in the JWT's scope claim via JwtGrantedAuthoritiesConverter.
 */
@RestController
@RequestMapping("/api/movies")
public class MovieController {

    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_catalog:read')")
    public List<Movie> list() {
        return List.of(
                new Movie(1L, "Inception", 2010),
                new Movie(2L, "Interstellar", 2014),
                new Movie(3L, "The Dark Knight", 2008)
        );
    }
}
