package com.cinetrack.security;

import com.cinetrack.recommendation.Movie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Security filter chain tests for the reactive recommendation endpoint.
 *
 * Spring Boot 4 removed the {@code @WebFluxTest} slice annotation and no longer
 * auto-configures {@link WebTestClient}. The client is built via
 * {@link WebTestClient#bindToApplicationContext(ApplicationContext)} so that
 * {@code mockJwt()}: which injects authentication into the reactive security
 * context in-process: can reach the {@link SecurityWebFilterChain} without
 * starting a real HTTP server.
 *
 * {@code springSecurity()} registers the {@code SecurityWebFilterChain} with the
 * mock WebFlux runtime. {@code mockJwt()} then short-circuits JWT decoding by
 * injecting a pre-built {@code JwtAuthenticationToken}.
 */
@SpringBootTest
class ReactiveSecurityTest {

    @Autowired
    private ApplicationContext applicationContext;

    private WebTestClient client;

    @BeforeEach
    void setUp() {
        client = WebTestClient
                .bindToApplicationContext(applicationContext)
                .apply(springSecurity())
                .build();
    }

    // ── 401: no token at all ─────────────────────────────────────────────────

    @Test
    void noToken_returns401() {
        client.get()
                .uri("/api/catalog/recommendations")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── 403: authenticated but missing the required scope ────────────────────

    @Test
    void wrongScope_returns403() {
        client.mutateWith(mockJwt()
                        .authorities(new SimpleGrantedAuthority("SCOPE_catalog:write")))
                .get()
                .uri("/api/catalog/recommendations")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void noScope_returns403() {
        client.mutateWith(mockJwt())
                .get()
                .uri("/api/catalog/recommendations")
                .exchange()
                .expectStatus().isForbidden();
    }

    // ── 200: valid JWT with catalog:read scope ────────────────────────────────

    @Test
    void validScope_returnsMovieFeed() {
        client.mutateWith(mockJwt()
                        .authorities(new SimpleGrantedAuthority("SCOPE_catalog:read")))
                .get()
                .uri("/api/catalog/recommendations")
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(Movie.class)
                .hasSize(5);
    }

    @Test
    void validScope_userEndpoint_returnsSubset() {
        client.mutateWith(mockJwt()
                        .authorities(new SimpleGrantedAuthority("SCOPE_catalog:read"))
                        .jwt(jwt -> jwt.subject("user-42")))
                .get()
                .uri("/api/catalog/recommendations/user-42")
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(Movie.class)
                .hasSize(3);
    }

    // ── Flux content verification ─────────────────────────────────────────────

    @Test
    void validScope_firstMovieIsShawshank() {
        client.mutateWith(mockJwt()
                        .authorities(new SimpleGrantedAuthority("SCOPE_catalog:read")))
                .get()
                .uri("/api/catalog/recommendations")
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(Movie.class)
                .value(movies -> {
                    assert movies.get(0).title().equals("The Shawshank Redemption");
                    assert movies.get(0).rating() == 9.3;
                });
    }
}
