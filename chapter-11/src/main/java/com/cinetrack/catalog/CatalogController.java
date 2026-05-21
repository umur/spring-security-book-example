package com.cinetrack.catalog;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Catalog API: requires SCOPE_catalog:read (enforced by SecurityConfig).
 *
 * The detail endpoint injects the Jwt directly via @AuthenticationPrincipal to
 * demonstrate per-request claim access without going through SecurityContext.
 * This is useful when response content varies by subscription tier or issuer.
 */
@RestController
@RequestMapping("/api/catalog/movies")
public class CatalogController {

    private static final List<Movie> CATALOG = List.of(
            new Movie(1L, "Inception", 2010, "Science Fiction"),
            new Movie(2L, "Interstellar", 2014, "Science Fiction"),
            new Movie(3L, "The Dark Knight", 2008, "Action"),
            new Movie(4L, "Parasite", 2019, "Thriller"),
            new Movie(5L, "Everything Everywhere All at Once", 2022, "Science Fiction")
    );

    @GetMapping
    public List<Movie> list() {
        return CATALOG;
    }

    /**
     * Returns movie detail alongside selected JWT claims to illustrate how a
     * resource server can use token metadata (issuer, tier, subject) at the
     * handler level without coupling to the security framework in business logic.
     */
    @GetMapping("/{id}")
    public Map<String, Object> detail(
            @PathVariable Long id,
            @AuthenticationPrincipal Jwt jwt
    ) {
        Movie movie = CATALOG.stream()
                .filter(m -> m.id().equals(id))
                .findFirst()
                .orElseThrow(() -> new MovieNotFoundException(id));

        return Map.of(
                "movie", movie,
                "requestedBy", jwt.getSubject(),
                "issuer", jwt.getIssuer().toString(),
                "tier", jwt.getClaimAsString("tier") != null
                        ? jwt.getClaimAsString("tier")
                        : "STANDARD"
        );
    }
}
