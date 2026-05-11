package com.cinetrack.security;

import com.cinetrack.recommendation.Movie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Instant;
import java.util.List;

/**
 * Full-pipeline integration test using real signed JWTs.
 *
 * The {@link JwtEncoder} mints tokens using the RSA key pair from {@link JwkConfig}.
 * The resource server decodes them via the same key — no mocking, no external
 * authorization server. This test verifies that
 * {@code ReactiveSecurityContextHolder.getContext()} resolves correctly within
 * the handler: if the principal is not propagated through the reactive chain,
 * the {@code Mono<Jwt>} parameter would be empty and the controller returns
 * an empty body.
 *
 * Uses {@code RANDOM_PORT} with a plain {@link WebTestClient#bindToServer()}
 * because real tokens travel over HTTP — no in-process security context injection.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ReactiveContextTest {

    @LocalServerPort
    private int port;

    @Autowired
    private JwtEncoder jwtEncoder;

    private WebTestClient webTestClient;

    @BeforeEach
    void setUp() {
        webTestClient = WebTestClient
                .bindToServer()
                .baseUrl("http://localhost:" + port)
                .build();
    }

    @Test
    void authenticatedRequest_contextPropagatesCorrectly() {
        String token = mintToken("user-99", List.of("catalog:read"));

        webTestClient.get()
                .uri("/api/catalog/recommendations")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(Movie.class)
                .hasSize(5);
    }

    @Test
    void authenticatedRequest_userEndpoint_contextPropagates() {
        String token = mintToken("user-99", List.of("catalog:read"));

        webTestClient.get()
                .uri("/api/catalog/recommendations/user-99")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(Movie.class)
                .hasSize(3);
    }

    @Test
    void expiredToken_returns401() {
        String token = mintExpiredToken("user-99", List.of("catalog:read"));

        webTestClient.get()
                .uri("/api/catalog/recommendations")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private String mintToken(String subject, List<String> scopes) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("https://auth.cinetrack.io")
                .subject(subject)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .claim("scope", String.join(" ", scopes))
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    private String mintExpiredToken(String subject, List<String> scopes) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("https://auth.cinetrack.io")
                .subject(subject)
                .issuedAt(Instant.now().minusSeconds(7200))
                .expiresAt(Instant.now().minusSeconds(3600))
                .claim("scope", String.join(" ", scopes))
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }
}
