package com.cinetrack.recommendation;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Recommendation endpoint demonstrating method-level security in a reactive context.
 *
 * {@code @PreAuthorize} evaluates against the reactive security context — Spring
 * Security's AOP advice unwraps the {@code Mono<Authentication>} from
 * {@link org.springframework.security.core.context.ReactiveSecurityContextHolder}
 * before the method body executes.
 *
 * This means the authority check happens before the handler subscribes to the
 * returned {@code Flux}, which is the correct reactive execution order.
 */
@RestController
@RequestMapping("/api/recommendations")
public class RecommendationController {

    private static final List<Movie> CATALOG = List.of(
            new Movie("tt0111161", "The Shawshank Redemption", "Drama",  9.3),
            new Movie("tt0068646", "The Godfather",            "Crime",  9.2),
            new Movie("tt0468569", "The Dark Knight",          "Action", 9.0),
            new Movie("tt0071562", "The Godfather Part II",    "Crime",  9.0),
            new Movie("tt0050083", "12 Angry Men",             "Drama",  9.0)
    );

    /**
     * Returns the recommendation feed.
     *
     * The {@code @PreAuthorize} annotation enforces the scope check at the
     * method boundary. If the caller lacks {@code SCOPE_catalog:read}, Spring
     * Security raises an {@link org.springframework.security.access.AccessDeniedException}
     * before the Flux is even constructed — resulting in a 403 response.
     */
    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_catalog:read')")
    public Flux<Movie> recommendations(@AuthenticationPrincipal Mono<Jwt> jwtMono) {
        return jwtMono
                .doOnNext(jwt -> System.out.printf(
                        "[RecommendationController] issuer=%s subject=%s%n",
                        jwt.getIssuer(), jwt.getSubject()))
                .thenMany(Flux.fromIterable(CATALOG));
    }
}
