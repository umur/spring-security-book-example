package com.example.security.headers;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
class SecurityHeadersIntegrationTest {

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
    // All headers present on /api/info
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("All security headers present on /api/info")
    class AllHeadersOnInfo {

        @Test
        @DisplayName("X-Content-Type-Options: nosniff is present in real HTTP response")
        void xContentTypeOptionsPresent() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("alice", "alice")
                    .getForEntity("/api/info", String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
        }

        @Test
        @DisplayName("X-Frame-Options: DENY is present in real HTTP response")
        void xFrameOptionsPresent() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("alice", "alice")
                    .getForEntity("/api/info", String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst("X-Frame-Options")).isEqualTo("DENY");
        }

        @Test
        @DisplayName("Strict-Transport-Security header is present in real HTTP response")
        void hstsPresent() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("alice", "alice")
                    .getForEntity("/api/info", String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst("Strict-Transport-Security")).isNotNull();
            assertThat(response.getHeaders().getFirst("Strict-Transport-Security"))
                    .contains("max-age=", "includeSubDomains");
        }

        @Test
        @DisplayName("Content-Security-Policy header is present in real HTTP response")
        void cspPresent() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("alice", "alice")
                    .getForEntity("/api/info", String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst("Content-Security-Policy")).isNotNull();
            assertThat(response.getHeaders().getFirst("Content-Security-Policy"))
                    .contains("default-src");
        }

        @Test
        @DisplayName("Referrer-Policy header is present in real HTTP response")
        void referrerPolicyPresent() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("alice", "alice")
                    .getForEntity("/api/info", String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst("Referrer-Policy")).isNotNull();
        }

        @Test
        @DisplayName("Permissions-Policy header is present in real HTTP response")
        void permissionsPolicyPresent() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("alice", "alice")
                    .getForEntity("/api/info", String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst("Permissions-Policy")).isNotNull();
            assertThat(response.getHeaders().getFirst("Permissions-Policy"))
                    .contains("camera=()", "microphone=()");
        }

        @Test
        @DisplayName("Cache-Control header is present in real HTTP response")
        void cacheControlPresent() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("alice", "alice")
                    .getForEntity("/api/info", String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst("Cache-Control")).isNotNull();
            assertThat(response.getHeaders().getFirst("Cache-Control"))
                    .contains("no-cache", "no-store");
        }
    }

    // -------------------------------------------------------------------------
    // /api/headers endpoint full HTTP
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("/api/headers endpoint full HTTP")
    class HeadersEndpointIT {

        @Test
        @DisplayName("GET /api/headers returns 200 with all security headers in real HTTP response")
        void headersEndpointReturnsAllSecurityHeaders() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("alice", "alice")
                    .getForEntity("/api/headers", String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
            assertThat(response.getHeaders().getFirst("X-Frame-Options")).isEqualTo("DENY");
            assertThat(response.getHeaders().getFirst("Strict-Transport-Security")).isNotNull();
            assertThat(response.getHeaders().getFirst("Content-Security-Policy")).isNotNull();
            assertThat(response.getHeaders().getFirst("Referrer-Policy")).isNotNull();
            assertThat(response.getHeaders().getFirst("Permissions-Policy")).isNotNull();
            assertThat(response.getHeaders().getFirst("Cache-Control")).isNotNull();
        }

        @Test
        @DisplayName("GET /api/headers without credentials returns 401")
        void headersEndpointUnauthenticatedReturns401() {
            ResponseEntity<String> response = restTemplate.getForEntity("/api/headers", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }
}
