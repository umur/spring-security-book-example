package com.cinetrack.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestClient;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for the token issuance endpoint.
 *
 * Verifies that {@code POST /api/token} returns a parseable JWT containing
 * the expected claims. Uses the application's own {@link JwtDecoder} bean to
 * decode the issued token — same key, same algorithm.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class TokenIssuanceTest {

    @LocalServerPort
    int port;

    @Autowired
    JwtDecoder jwtDecoder;

    RestClient client;

    @BeforeEach
    void setUp() {
        client = RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .build();
    }

    @Test
    @SuppressWarnings("unchecked")
    void postToken_returnsJwt() {
        Map<String, String> body = client.post()
                .uri("/api/token?username=alice")
                .retrieve()
                .body(Map.class);

        assertThat(body).isNotNull().containsKey("token");
        assertThat(body.get("token")).isNotBlank();
    }

    @Test
    @SuppressWarnings("unchecked")
    void issuedJwt_containsExpectedClaims() {
        Map<String, String> body = client.post()
                .uri("/api/token?username=alice")
                .retrieve()
                .body(Map.class);

        String rawToken = body.get("token");
        var jwt = jwtDecoder.decode(rawToken);

        assertThat(jwt.getSubject()).isEqualTo("alice");
        assertThat(jwt.getClaimAsString("iss")).isEqualTo("cinetrack");
        assertThat(jwt.getClaimAsString("scope")).isEqualTo("catalog:read");
        assertThat(jwt.getExpiresAt()).isAfter(jwt.getIssuedAt());
    }
}
