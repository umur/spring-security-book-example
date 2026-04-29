package com.example.security.cors;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static com.example.security.cors.config.SecurityConfig.TRUSTED_ORIGIN;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
class CorsIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17-alpine");

    @DynamicPropertySource
    static void configureDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
    }

    @Autowired
    private TestRestTemplate restTemplate;

    // -------------------------------------------------------------------------
    // Preflight full HTTP flow
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Preflight full HTTP integration")
    class PreflightIT {

        @Test
        @DisplayName("OPTIONS /api/public from any origin returns 200 with CORS headers")
        void preflightPublicReturnsOk() {
            HttpHeaders headers = new HttpHeaders();
            headers.set(HttpHeaders.ORIGIN, "https://random.example.com");
            headers.set(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET");

            ResponseEntity<Void> response = restTemplate.exchange(
                    "/api/public", HttpMethod.OPTIONS,
                    new HttpEntity<>(headers), Void.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)).isNotNull();
        }

        @Test
        @DisplayName("OPTIONS /api/data from trusted origin returns correct CORS headers")
        void preflightRestrictedFromTrustedOriginReturnsOk() {
            HttpHeaders headers = new HttpHeaders();
            headers.set(HttpHeaders.ORIGIN, TRUSTED_ORIGIN);
            headers.set(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST");
            headers.set(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "Authorization,Content-Type");

            ResponseEntity<Void> response = restTemplate.exchange(
                    "/api/data", HttpMethod.OPTIONS,
                    new HttpEntity<>(headers), Void.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN))
                    .isEqualTo(TRUSTED_ORIGIN);
        }
    }

    // -------------------------------------------------------------------------
    // Public endpoint full HTTP flow
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Public endpoint full HTTP CORS")
    class PublicEndpointIT {

        @Test
        @DisplayName("GET /api/public from any origin returns 200 with Access-Control-Allow-Origin")
        void publicEndpointAllowsAnyOrigin() {
            HttpHeaders headers = new HttpHeaders();
            headers.set(HttpHeaders.ORIGIN, "https://any.origin.com");

            ResponseEntity<String> response = restTemplate.exchange(
                    "/api/public", HttpMethod.GET,
                    new HttpEntity<>(headers), String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)).isNotNull();
        }
    }

    // -------------------------------------------------------------------------
    // Restricted endpoint full HTTP flow
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Restricted endpoint full HTTP CORS")
    class RestrictedEndpointIT {

        @Test
        @DisplayName("GET /api/data from trusted origin as authenticated user returns CORS header")
        void restrictedEndpointTrustedOriginAuthenticated() {
            HttpHeaders headers = new HttpHeaders();
            headers.set(HttpHeaders.ORIGIN, TRUSTED_ORIGIN);

            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("alice", "alice")
                    .exchange("/api/data", HttpMethod.GET,
                            new HttpEntity<>(headers), String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN))
                    .isEqualTo(TRUSTED_ORIGIN);
        }

        @Test
        @DisplayName("GET /api/data from untrusted origin as authenticated user returns no CORS header")
        void restrictedEndpointUntrustedOriginNoCorsHeader() {
            HttpHeaders headers = new HttpHeaders();
            headers.set(HttpHeaders.ORIGIN, "https://evil.example.com");

            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("alice", "alice")
                    .exchange("/api/data", HttpMethod.GET,
                            new HttpEntity<>(headers), String.class);

            assertThat(response.getHeaders().getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)).isNull();
        }

        @Test
        @DisplayName("GET /api/data without credentials returns 401")
        void restrictedEndpointUnauthenticatedReturns401() {
            HttpHeaders headers = new HttpHeaders();
            headers.set(HttpHeaders.ORIGIN, TRUSTED_ORIGIN);

            ResponseEntity<String> response = restTemplate.exchange(
                    "/api/data", HttpMethod.GET,
                    new HttpEntity<>(headers), String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }
}
