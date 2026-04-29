package com.example.security.testing;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Full HTTP integration testing reference using TestRestTemplate.
 *
 * TestRestTemplate differences from MockMvc:
 *   - Starts a real embedded server on a random port (RANDOM_PORT)
 *   - Follows HTTP redirects by default (configurable)
 *   - Uses actual HTTP Basic via .withBasicAuth(user, pass)
 *   - No MockMvc post-processors — authentication is real
 *   - Great for end-to-end smoke tests; less granular than MockMvc
 *
 * Spring Boot 4 imports:
 *   TestRestTemplate        → org.springframework.boot.resttestclient.TestRestTemplate
 *   @AutoConfigureTestRestTemplate → org.springframework.boot.resttestclient.autoconfigure
 *
 * Note: This test class uses H2 (in-memory), so no Testcontainers are needed.
 * The DataSeeder seeds user/user (ROLE_USER) and admin/admin (ROLE_ADMIN).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
class TestRestTemplateSecurityTest {

    @Autowired
    TestRestTemplate restTemplate;

    // =========================================================================
    // Public endpoint — no credentials required
    // =========================================================================

    @Nested
    @DisplayName("GET /api/public — unauthenticated access")
    class PublicEndpoint {

        @Test
        @DisplayName("GET /api/public without credentials returns 200")
        void publicEndpointIsAccessible() {
            ResponseEntity<String> response = restTemplate.getForEntity("/api/public", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("public");
        }
    }

    // =========================================================================
    // HTTP Basic authentication
    // =========================================================================

    @Nested
    @DisplayName("HTTP Basic authentication via TestRestTemplate")
    class HttpBasic {

        @Test
        @DisplayName("valid user credentials access /api/user")
        void validUserCredentialsGrantAccess() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("user", "user")
                    .getForEntity("/api/user", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("Hello, user");
        }

        @Test
        @DisplayName("invalid credentials return 401")
        void invalidCredentialsReturn401() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("user", "wrong")
                    .getForEntity("/api/user", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("valid admin credentials access /api/admin")
        void adminCredentialsGrantAdminAccess() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("admin", "admin")
                    .getForEntity("/api/admin", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("Admin resource");
        }

        @Test
        @DisplayName("user credentials denied for /api/admin — returns 403")
        void userCredentialsDeniedForAdmin() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("user", "user")
                    .getForEntity("/api/admin", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }

        @Test
        @DisplayName("unknown user returns 401")
        void unknownUserReturns401() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("nobody", "secret")
                    .getForEntity("/api/user", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    // =========================================================================
    // Unauthenticated access to protected resources
    // =========================================================================

    @Nested
    @DisplayName("Unauthenticated access — redirect / login page behaviour")
    class UnauthenticatedAccess {

        @Test
        @DisplayName("unauthenticated /api/user follows redirect to login page (200 with login content)")
        void unauthenticatedUserEndpointRedirectsToLogin() {
            // TestRestTemplate follows redirects by default — the final response is the
            // login page (200 OK) rather than the raw 302. We verify the body contains
            // the authentication hint to confirm the redirect happened.
            ResponseEntity<String> response = restTemplate.getForEntity("/api/user", String.class);
            // Either 401 (HTTP Basic challenge) or 200 with login page content after redirect
            assertThat(response.getStatusCode().value())
                    .as("Unauthenticated request should result in 401 or redirect to login (200)")
                    .isIn(401, 200);
            if (response.getStatusCode() == HttpStatus.OK) {
                assertThat(response.getBody()).contains("Authentication required");
            }
        }

        @Test
        @DisplayName("unauthenticated /api/admin follows redirect to login page or returns 401")
        void unauthenticatedAdminEndpointRedirectsToLogin() {
            ResponseEntity<String> response = restTemplate.getForEntity("/api/admin", String.class);
            assertThat(response.getStatusCode().value())
                    .as("Unauthenticated request should result in 401 or redirect to login (200)")
                    .isIn(401, 200);
            if (response.getStatusCode() == HttpStatus.OK) {
                assertThat(response.getBody()).contains("Authentication required");
            }
        }
    }

    // =========================================================================
    // Security headers present in real HTTP responses
    // =========================================================================

    @Nested
    @DisplayName("Security headers in real HTTP responses")
    class SecurityHeaders {

        @Test
        @DisplayName("Response from /api/user contains X-Content-Type-Options header")
        void xContentTypeOptionsPresent() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("user", "user")
                    .getForEntity("/api/user", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst("X-Content-Type-Options"))
                    .isEqualTo("nosniff");
        }

        @Test
        @DisplayName("Response from /api/user contains X-Frame-Options: DENY")
        void xFrameOptionsPresent() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("user", "user")
                    .getForEntity("/api/user", String.class);
            assertThat(response.getHeaders().getFirst("X-Frame-Options"))
                    .isEqualTo("DENY");
        }

        @Test
        @DisplayName("Response from /api/public also has security headers")
        void publicEndpointHasSecurityHeaders() {
            ResponseEntity<String> response = restTemplate.getForEntity("/api/public", String.class);
            assertThat(response.getHeaders().containsHeader("X-Content-Type-Options")).isTrue();
        }
    }
}
