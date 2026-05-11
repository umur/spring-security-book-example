package com.cinetrack.catalog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Public-facing API for the catalog-service.
 *
 * In a zero-trust deployment the caller is always another service — there is
 * no end-user browser here. Logging the {@code sub} claim lets the operations
 * team trace which service made the call without decrypting the token body.
 *
 * The {@link Jwt} principal is injected by Spring Security after the
 * {@link com.cinetrack.security.AudienceValidator} has already confirmed the
 * token was issued for this specific service.
 */
@RestController
@RequestMapping("/api/catalog")
public class CatalogController {

    private static final Logger log = LoggerFactory.getLogger(CatalogController.class);

    @GetMapping("/movies")
    public List<Movie> listMovies(@AuthenticationPrincipal Jwt jwt) {
        // sub claim holds the service identity (e.g. "recommendation-service")
        log.info("catalog-service accessed by service principal: {}", jwt.getSubject());
        return List.of(
                new Movie(1L, "Inception", 2010),
                new Movie(2L, "Interstellar", 2014),
                new Movie(3L, "The Dark Knight", 2008),
                new Movie(4L, "Parasite", 2019),
                new Movie(5L, "Everything Everywhere All at Once", 2022)
        );
    }
}
