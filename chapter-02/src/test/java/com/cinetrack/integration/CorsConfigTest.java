package com.cinetrack.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for CORS policy.
 *
 * Preflight requests (OPTIONS) are sent without credentials, which is how
 * browsers issue them. The CORS headers on the response determine whether
 * the browser will allow the actual cross-origin request to proceed.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class CorsConfigTest {

    @LocalServerPort
    int port;

    RestClient client;

    @BeforeEach
    void setUp() {
        client = RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .build();
    }

    @Test
    void preflight_fromTrustedOrigin_returnsCorsHeaders() {
        ResponseEntity<Void> response = client.options()
                .uri("/api/movies")
                .header("Origin", "http://localhost:3000")
                .header("Access-Control-Request-Method", "GET")
                .retrieve()
                .onStatus(status -> true, (req, res) -> {})
                .toBodilessEntity();

        assertThat(response.getHeaders().getFirst("Access-Control-Allow-Origin"))
                .isEqualTo("http://localhost:3000");
    }

    @Test
    void preflight_fromUntrustedOrigin_hasNoCorsAllowOriginHeader() {
        ResponseEntity<Void> response = client.options()
                .uri("/api/movies")
                .header("Origin", "http://evil.example.com")
                .header("Access-Control-Request-Method", "GET")
                .retrieve()
                .onStatus(status -> true, (req, res) -> {})
                .toBodilessEntity();

        // Spring Security returns 403 for disallowed CORS origins: no allow header.
        assertThat(response.getHeaders().getFirst("Access-Control-Allow-Origin"))
                .isNull();
    }
}
