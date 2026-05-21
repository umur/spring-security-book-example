package com.cinetrack.recommendation;

import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;

/**
 * Recommendation endpoint.
 *
 * Fetches the movie catalog from catalog-service using the catalogClient WebClient,
 * which automatically attaches a client-credentials Bearer token via the
 * ServletOAuth2AuthorizedClientExchangeFilterFunction configured in OAuth2ClientConfig.
 *
 * The recommendation logic here is intentionally trivial: this chapter is about
 * the OAuth2 client mechanics, not recommendation algorithms.
 */
@RestController
@RequestMapping("/api/recommendations")
public class RecommendationController {

    private final WebClient catalogClient;

    public RecommendationController(WebClient catalogClient) {
        this.catalogClient = catalogClient;
    }

    @GetMapping
    public List<Recommendation> recommend() {
        List<CatalogMovie> movies = catalogClient.get()
                .uri("/api/catalog/movies")
                .attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
                        .clientRegistrationId("catalog-cc"))
                .retrieve()
                .bodyToFlux(CatalogMovie.class)
                .collectList()
                .block();

        if (movies == null) {
            return List.of();
        }

        // Wrap each movie as a recommendation with a static reason.
        // In production this would use watch history, ratings, ML scores, etc.
        return movies.stream()
                .map(m -> new Recommendation(m.id(), m.title(), m.year(), "Trending this week"))
                .toList();
    }
}
