package com.cinetrack.headers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that the security headers configured in SecurityConfig are present
 * on every authenticated response.
 *
 * Uses a real embedded server (RANDOM_PORT) rather than MockMvc so that the
 * full servlet filter chain -- including the HttpFirewall and all security
 * filters -- is exercised.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SecurityHeadersTest {

    @LocalServerPort
    int port;

    RestClient client;

    @BeforeEach
    void setUp() {
        String credentials = Base64.getEncoder().encodeToString("alice:password".getBytes());
        client = RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultHeader("Authorization", "Basic " + credentials)
                .build();
    }

    @Test
    void response_hasXContentTypeOptionsHeader() {
        ResponseEntity<Void> response = client.get()
                .uri("/api/movies")
                .retrieve()
                .toBodilessEntity();

        assertThat(response.getHeaders().getFirst("X-Content-Type-Options"))
                .isEqualTo("nosniff");
    }

    @Test
    void response_hasStrictTransportSecurityHeader() {
        ResponseEntity<Void> response = client.get()
                .uri("/api/movies")
                .retrieve()
                .toBodilessEntity();

        String hsts = response.getHeaders().getFirst("Strict-Transport-Security");
        assertThat(hsts).isNotNull();
        assertThat(hsts).contains("max-age=31536000");
        assertThat(hsts).contains("includeSubDomains");
    }

    @Test
    void response_hasXFrameOptionsDeny() {
        ResponseEntity<Void> response = client.get()
                .uri("/api/movies")
                .retrieve()
                .toBodilessEntity();

        assertThat(response.getHeaders().getFirst("X-Frame-Options"))
                .isEqualTo("DENY");
    }

    @Test
    void response_hasContentSecurityPolicyHeader() {
        ResponseEntity<Void> response = client.get()
                .uri("/api/movies")
                .retrieve()
                .toBodilessEntity();

        String csp = response.getHeaders().getFirst("Content-Security-Policy");
        assertThat(csp).isNotNull();
        assertThat(csp).contains("default-src 'self'");
    }
}
