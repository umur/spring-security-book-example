package com.cinetrack.catalog;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * HTTP client for catalog-service.
 *
 * Delegates to the catalogWebClient bean produced by OAuth2ClientConfig, which is
 * already pre-configured with a ServletOAuth2AuthorizedClientExchangeFilterFunction.
 * Every outbound request automatically carries a client-credentials Bearer token;
 * the token lifecycle (fetch, cache, refresh) is handled by OAuth2AuthorizedClientManager.
 */
@Component
public class CatalogClient {

    private final WebClient webClient;

    public CatalogClient(@Qualifier("catalogWebClient") WebClient webClient) {
        this.webClient = webClient;
    }

    /** Fetches all movies from catalog-service. */
    public Flux<Movie> fetchMovies() {
        return webClient.get()
                .uri("/api/catalog/movies")
                .attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
                        .clientRegistrationId("catalog-cc"))
                .retrieve()
                .bodyToFlux(Movie.class);
    }

    /** Fetches a single movie by id. */
    public Mono<Movie> fetchMovie(String id) {
        return webClient.get()
                .uri("/api/catalog/movies/{id}", id)
                .attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
                        .clientRegistrationId("catalog-cc"))
                .retrieve()
                .bodyToMono(Movie.class);
    }
}
