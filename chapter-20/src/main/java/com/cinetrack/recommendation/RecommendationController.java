package com.cinetrack.recommendation;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Reactive recommendation endpoint for the CineTrack catalog service.
 *
 * Notice that {@code @AuthenticationPrincipal} in a WebFlux controller receives
 * a {@code Mono<Jwt>} rather than a plain {@code Jwt}. Spring Security resolves
 * the principal lazily from the reactive security context — subscribing only
 * when the handler subscribes to the {@code Mono}.
 *
 * The stub data keeps the chapter focused on security mechanics rather than
 * persistence; in production this would delegate to a recommendation engine.
 */
@RestController
@RequestMapping("/api/catalog/recommendations")
public class RecommendationController {

    private static final List<Movie> CATALOG = List.of(
            new Movie("tt0111161", "The Shawshank Redemption", "Drama",    9.3),
            new Movie("tt0068646", "The Godfather",            "Crime",    9.2),
            new Movie("tt0468569", "The Dark Knight",          "Action",   9.0),
            new Movie("tt0071562", "The Godfather Part II",    "Crime",    9.0),
            new Movie("tt0050083", "12 Angry Men",             "Drama",    9.0)
    );

    /**
     * Returns the full recommendation feed as a streaming {@link Flux}.
     *
     * The {@code Mono<Jwt>} principal is flat-mapped so the subject claim can
     * be logged or used for personalisation without blocking.
     */
    @GetMapping
    public Flux<Movie> recommendations(@AuthenticationPrincipal Mono<Jwt> jwtMono) {
        return jwtMono
                .doOnNext(jwt -> logRequest(jwt.getSubject(), "global feed"))
                .thenMany(Flux.fromIterable(CATALOG));
    }

    /**
     * Returns personalised recommendations for a specific user.
     *
     * In a real system the {@code userId} would gate the result against the
     * JWT subject so users cannot fetch each other's private feeds.
     */
    @GetMapping("/{userId}")
    public Mono<List<Movie>> recommendationsForUser(
            @PathVariable String userId,
            @AuthenticationPrincipal Mono<Jwt> jwtMono) {

        return jwtMono
                .doOnNext(jwt -> logRequest(jwt.getSubject(), "user/" + userId))
                .thenReturn(CATALOG.subList(0, 3));
    }

    private void logRequest(String subject, String path) {
        // In production: structured logging with MDC or a reactive audit sink.
        System.out.printf("[RecommendationController] subject=%s path=%s%n", subject, path);
    }
}
