package com.cinetrack.catalog;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Exposes the movie catalog to authenticated users.
 *
 * Access control is enforced entirely at the filter chain level by
 * {@code SubscriptionTierAuthorizationManager} — this controller has no
 * security annotations of its own. The separation keeps HTTP handling and
 * authorization policy in separate, independently testable units.
 */
@RestController
@RequestMapping("/api/catalog")
public class CatalogController {

    @GetMapping("/movies")
    public ResponseEntity<List<Map<String, Object>>> listMovies() {
        return ResponseEntity.ok(List.of(
                Map.of("id", 1, "title", "Inception"),
                Map.of("id", 2, "title", "The Dark Knight")
        ));
    }

    @GetMapping("/movies/premium")
    public ResponseEntity<List<Map<String, Object>>> listPremiumMovies() {
        return ResponseEntity.ok(List.of(
                Map.of("id", 3, "title", "Oppenheimer", "tier", "PREMIUM"),
                Map.of("id", 4, "title", "Dune: Part Two", "tier", "PREMIUM")
        ));
    }
}
