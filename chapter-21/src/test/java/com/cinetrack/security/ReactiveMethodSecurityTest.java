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
 * Integration tests for {@code @PreAuthorize} method security on the reactive
 * recommendation endpoint.
 *
 * Uses {@link WebTestClient#bindToApplicationContext(ApplicationContext)} so the
 * full Spring application context is active — including the reactive method
 * security AOP advice that evaluates {@code @PreAuthorize}. Without this,
 * method-level security is bypassed.
 *
 * {@code springSecurity()} registers the {@link SecurityWebFilterChain} with the
 * mock runtime. {@code mockJwt()} injects pre-built authentication tokens so no
 * real authorization server is needed.
 */
@SpringBootTest
class ReactiveMethodSecurityTest {

    @Autowired
    private ApplicationContext applicationContext;

    private WebTestClient webTestClient;

    @BeforeEach
    void setUp() {
        webTestClient = WebTestClient
                .bindToApplicationContext(applicationContext)
                .apply(springSecurity())
                .build();
    }

    // ── @PreAuthorize blocks missing scope ────────────────────────────────────

    @Test
    void missingCatalogRead_returns403() {
        webTestClient
                .mutateWith(mockJwt()
                        .jwt(jwt -> jwt
                                .issuer(MultiTenantJwtDecoderConfig.ISSUER_1)
                                .subject("user-no-scope"))
                        .authorities(new SimpleGrantedAuthority("SCOPE_catalog:write")))
                .get()
                .uri("/api/recommendations")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void noAuthorities_returns403() {
        webTestClient
                .mutateWith(mockJwt()
                        .jwt(jwt -> jwt
                                .issuer(MultiTenantJwtDecoderConfig.ISSUER_1)
                                .subject("user-no-authorities")))
                .get()
                .uri("/api/recommendations")
                .exchange()
                .expectStatus().isForbidden();
    }

    // ── @PreAuthorize allows catalog:read ─────────────────────────────────────

    @Test
    void withCatalogRead_returns200AndMovies() {
        webTestClient
                .mutateWith(mockJwt()
                        .jwt(jwt -> jwt
                                .issuer(MultiTenantJwtDecoderConfig.ISSUER_1)
                                .subject("user-with-scope"))
                        .authorities(new SimpleGrantedAuthority("SCOPE_catalog:read")))
                .get()
                .uri("/api/recommendations")
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(Movie.class)
                .hasSize(5);
    }

    @Test
    void withCatalogReadAndTier_returns200() {
        webTestClient
                .mutateWith(mockJwt()
                        .jwt(jwt -> jwt
                                .issuer(MultiTenantJwtDecoderConfig.ISSUER_2)
                                .subject("ultra-user")
                                .claim("tier", "ULTRA"))
                        .authorities(
                                new SimpleGrantedAuthority("SCOPE_catalog:read"),
                                new SimpleGrantedAuthority("TIER_ULTRA")))
                .get()
                .uri("/api/recommendations")
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(Movie.class)
                .hasSize(5);
    }

    // ── no token → 401 ───────────────────────────────────────────────────────

    @Test
    void noToken_returns401() {
        webTestClient.get()
                .uri("/api/recommendations")
                .exchange()
                .expectStatus().isUnauthorized();
    }
}
