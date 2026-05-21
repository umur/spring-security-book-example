package com.cinetrack.catalog;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Catalog API: requires authentication (enforced by SecurityConfig).
 *
 * GET /movies     : authenticated
 * GET /movies/{id}: authenticated
 */
@RestController
@RequestMapping("/api/catalog/movies")
public class CatalogController {

    private static final List<Movie> CATALOG = List.of(
            new Movie("1", "Inception", "Science Fiction"),
            new Movie("2", "Interstellar", "Science Fiction"),
            new Movie("3", "The Dark Knight", "Action")
    );

    @GetMapping
    public List<Movie> list() {
        return CATALOG;
    }

    @GetMapping("/{id}")
    public ResponseEntity<Movie> detail(@PathVariable String id) {
        return CATALOG.stream()
                .filter(m -> m.id().equals(id))
                .findFirst()
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}
