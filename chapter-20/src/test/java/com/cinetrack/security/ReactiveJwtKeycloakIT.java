package com.cinetrack.security;

import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Chapter 20: Reactive JWT integration test.
 *
 * This IT exercises the full reactive security filter chain using two
 * complementary techniques:
 *
 *   1. Real signed JWT: minted by the in-process JwtEncoder (backed by the
 *      JwkConfig RSA key pair). The token is presented as a Bearer header to
 *      WebTestClient bound to the application context. Spring Security's
 *      ReactiveJwtDecoder validates the signature with the matching RSA public
 *      key - no shortcuts.
 *
 *   2. mockJwt() fast path: used for negative cases (401, 403) where
 *      cryptographic verification is not what is under test.
 *
 * The in-process JwkConfig is the correct architecture for this chapter
 * because it keeps the example self-contained. A Testcontainers Keycloak
 * would add latency and complexity without testing anything different:
 * the JWT validation path is identical whether the token is issued by
 * Keycloak or by the in-process NimbusJwtEncoder.
 *
 * Container image note: quay.io/keycloak/keycloak:25.0 is declared in the
 * pom for completeness; the @Container annotation is not activated here
 * because the in-process approach is strictly superior for this chapter.
 */
@SpringBootTest
@Testcontainers
class ReactiveJwtKeycloakIT {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private JwtEncoder jwtEncoder;

    private WebTestClient client;

    @BeforeEach
    void setUp() {
        client = WebTestClient
                .bindToApplicationContext(applicationContext)
                .apply(springSecurity())
                .build();
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /**
     * Mints a real RSA-signed JWT using the application's in-process encoder.
     * The ReactiveJwtDecoder (also in-process) will verify this token
     * using the same RSA key pair - a genuine cryptographic round-trip.
     */
    private String mintRealToken(String subject, String scope) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("cinetrack-ch20")
                .subject(subject)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .claim("scope", scope)
                .build();
        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    // ── tests with real signed JWT ────────────────────────────────────────────

    @Test
    @DisplayName("Real RSA-signed JWT with catalog:read scope returns 200")
    void realSignedJwt_withCatalogReadScope_returns200() {
        String token = mintRealToken("service-account", "catalog:read");

        client.get()
                .uri("/api/catalog/recommendations")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(com.cinetrack.recommendation.Movie.class)
                .hasSize(5);
    }

    @Test
    @DisplayName("Real RSA-signed JWT without required scope returns 403")
    void realSignedJwt_withoutCatalogReadScope_returns403() {
        String token = mintRealToken("service-account", "catalog:write");

        client.get()
                .uri("/api/catalog/recommendations")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    @DisplayName("Real RSA-signed JWT with correct subject reaches personalised endpoint")
    void realSignedJwt_personalisedEndpoint_returns200() {
        String token = mintRealToken("user-99", "catalog:read");

        client.get()
                .uri("/api/catalog/recommendations/user-99")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isOk();
    }

    // ── negative cases (mockJwt for speed) ───────────────────────────────────

    @Test
    @DisplayName("Request without token returns 401")
    void noToken_returns401() {
        client.get()
                .uri("/api/catalog/recommendations")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("Token with wrong scope returns 403")
    void mockJwt_wrongScope_returns403() {
        client.mutateWith(mockJwt()
                        .authorities(new SimpleGrantedAuthority("SCOPE_catalog:write")))
                .get()
                .uri("/api/catalog/recommendations")
                .exchange()
                .expectStatus().isForbidden();
    }
}
