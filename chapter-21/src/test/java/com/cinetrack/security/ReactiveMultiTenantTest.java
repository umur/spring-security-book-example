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
 * Verifies that the multi-tenant resolver accepts tokens from either registered
 * issuer and rejects requests without a valid token.
 *
 * Uses {@link WebTestClient#bindToApplicationContext(ApplicationContext)} with
 * {@code springSecurity()} so that {@code mockJwt()} mutators are processed
 * in-process by the {@link SecurityWebFilterChain} — no real HTTP server needed.
 *
 * The issuer claim is set on the mock JWT so that any code inspecting
 * {@code jwt.getIssuer()} in the handler sees the expected value.
 */
@SpringBootTest
class ReactiveMultiTenantTest {

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

    // ── issuer 1 ─────────────────────────────────────────────────────────────

    @Test
    void issuer1_withCatalogRead_returns200() {
        client.mutateWith(mockJwt()
                        .jwt(jwt -> jwt
                                .issuer(MultiTenantJwtDecoderConfig.ISSUER_1)
                                .subject("user-from-issuer1"))
                        .authorities(new SimpleGrantedAuthority("SCOPE_catalog:read")))
                .get()
                .uri("/api/recommendations")
                .exchange()
                .expectStatus().isOk();
    }

    // ── issuer 2 ─────────────────────────────────────────────────────────────

    @Test
    void issuer2_withCatalogRead_returns200() {
        client.mutateWith(mockJwt()
                        .jwt(jwt -> jwt
                                .issuer(MultiTenantJwtDecoderConfig.ISSUER_2)
                                .subject("user-from-issuer2"))
                        .authorities(new SimpleGrantedAuthority("SCOPE_catalog:read")))
                .get()
                .uri("/api/recommendations")
                .exchange()
                .expectStatus().isOk();
    }

    // ── no token → 401 ───────────────────────────────────────────────────────

    @Test
    void noToken_returns401() {
        client.get()
                .uri("/api/recommendations")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── missing scope → 403 ───────────────────────────────────────────────────

    @Test
    void issuer1_missingScope_returns403() {
        client.mutateWith(mockJwt()
                        .jwt(jwt -> jwt.issuer(MultiTenantJwtDecoderConfig.ISSUER_1))
                        .authorities(new SimpleGrantedAuthority("SCOPE_catalog:write")))
                .get()
                .uri("/api/recommendations")
                .exchange()
                .expectStatus().isForbidden();
    }
}
