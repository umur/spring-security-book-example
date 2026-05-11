package com.cinetrack.catalog;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Catalog API — authorization enforced by SecurityConfig and @PreAuthorize.
 *
 * GET  /movies      — SCOPE_catalog:read
 * GET  /movies/{id} — SCOPE_catalog:read
 * POST /movies      — ROLE_ADMIN
 * DELETE /movies/{id} — ROLE_ADMIN
 */
@RestController
@RequestMapping("/api/catalog/movies")
public class CatalogController {

    private final List<Movie> catalog = new ArrayList<>(List.of(
            new Movie("1", "Inception", "Science Fiction"),
            new Movie("2", "Interstellar", "Science Fiction"),
            new Movie("3", "The Dark Knight", "Action")
    ));

    private final AtomicInteger idSequence = new AtomicInteger(4);

    @GetMapping
    public List<Movie> list() {
        return catalog;
    }

    @GetMapping("/{id}")
    public ResponseEntity<Movie> detail(@PathVariable String id) {
        return catalog.stream()
                .filter(m -> m.id().equals(id))
                .findFirst()
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Movie> create(@RequestBody Movie movie) {
        Movie created = new Movie(String.valueOf(idSequence.getAndIncrement()), movie.title(), movie.genre());
        catalog.add(created);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> delete(@PathVariable String id) {
        catalog.removeIf(m -> m.id().equals(id));
        return ResponseEntity.noContent().build();
    }
}
