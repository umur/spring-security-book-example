package com.example.security.passwordencoding;

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

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end integration test using a real PostgreSQL container.
 * Proves that the seeded users (whose passwords are BCrypt-encoded via
 * DelegatingPasswordEncoder) can authenticate over HTTP Basic, and that
 * the password encoding endpoints work end-to-end.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
@DisplayName("Password Encoding Integration Tests")
class PasswordEncodingIntegrationTest {

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

    @Nested
    @DisplayName("Authentication with encoded passwords")
    class AuthenticationWithEncodedPasswords {

        @Test
        @DisplayName("unauthenticated request to encode endpoint returns 401")
        void unauthenticatedReturns401() {
            ResponseEntity<String> response = restTemplate.getForEntity(
                    "/api/passwords/encode?raw=test", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("admin user seeded with bcrypt-encoded password can authenticate")
        void adminCanAuthenticateWithBcryptEncodedPassword() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("admin", "admin123")
                    .getForEntity("/api/passwords/info", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        @Test
        @DisplayName("regular user seeded with bcrypt-encoded password can authenticate")
        void userCanAuthenticateWithBcryptEncodedPassword() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("user", "user123")
                    .getForEntity("/api/passwords/info", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        @Test
        @DisplayName("wrong password returns 401")
        void wrongPasswordReturns401() {
            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("admin", "wrongPassword")
                    .getForEntity("/api/passwords/info", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    @Nested
    @DisplayName("Encode endpoint end-to-end")
    class EncodeEndToEnd {

        @Test
        @DisplayName("encode endpoint returns a non-empty encoded string")
        void encodeEndpointReturnsEncodedString() {
            ResponseEntity<Map> response = restTemplate
                    .withBasicAuth("admin", "admin123")
                    .getForEntity("/api/passwords/encode?raw=testPassword&algorithm=bcrypt", Map.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("encoded").toString()).isNotBlank();
            assertThat(response.getBody().get("algorithm")).isEqualTo("bcrypt");
        }

        @Test
        @DisplayName("delegating algorithm encodes with {bcrypt} prefix")
        void delegatingEncodeHasBcryptPrefix() {
            ResponseEntity<Map> response = restTemplate
                    .withBasicAuth("admin", "admin123")
                    .getForEntity("/api/passwords/encode?raw=testPassword&algorithm=delegating", Map.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("encoded").toString()).startsWith("{bcrypt}");
        }
    }

    @Nested
    @DisplayName("Verify endpoint end-to-end")
    class VerifyEndToEnd {

        @Test
        @DisplayName("verify returns true for matching password via delegating encoder")
        void verifyReturnsTrueForMatchingPassword() {
            // Step 1: encode
            ResponseEntity<Map> encodeResponse = restTemplate
                    .withBasicAuth("admin", "admin123")
                    .getForEntity("/api/passwords/encode?raw=myTestPass&algorithm=delegating", Map.class);

            assertThat(encodeResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            String encoded = encodeResponse.getBody().get("encoded").toString();

            // Step 2: verify
            Map<String, String> verifyBody = Map.of(
                    "raw", "myTestPass",
                    "encoded", encoded,
                    "algorithm", "delegating"
            );

            ResponseEntity<Map> verifyResponse = restTemplate
                    .withBasicAuth("admin", "admin123")
                    .postForEntity("/api/passwords/verify", verifyBody, Map.class);

            assertThat(verifyResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(verifyResponse.getBody().get("matches")).isEqualTo(true);
        }

        @Test
        @DisplayName("verify returns false for wrong password")
        void verifyReturnsFalseForWrongPassword() {
            ResponseEntity<Map> encodeResponse = restTemplate
                    .withBasicAuth("admin", "admin123")
                    .getForEntity("/api/passwords/encode?raw=correctPass&algorithm=delegating", Map.class);

            String encoded = encodeResponse.getBody().get("encoded").toString();

            Map<String, String> verifyBody = Map.of(
                    "raw", "wrongPass",
                    "encoded", encoded,
                    "algorithm", "delegating"
            );

            ResponseEntity<Map> verifyResponse = restTemplate
                    .withBasicAuth("admin", "admin123")
                    .postForEntity("/api/passwords/verify", verifyBody, Map.class);

            assertThat(verifyResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(verifyResponse.getBody().get("matches")).isEqualTo(false);
        }
    }
}
