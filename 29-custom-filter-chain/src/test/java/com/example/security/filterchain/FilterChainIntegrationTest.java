package com.example.security.filterchain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
class FilterChainIntegrationTest {

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
    @DisplayName("Public endpoint via HTTP")
    class PublicEndpoint {

        @Test
        @DisplayName("/api/public/info returns 200 without credentials")
        void publicInfoReturns200() {
            var response = restTemplate.getForEntity("/api/public/info", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("ok");
        }

        @Test
        @DisplayName("/api/public/info response carries X-Rate-Limit-Remaining header")
        void publicInfoHasRateLimitHeader() {
            var response = restTemplate.getForEntity("/api/public/info", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst("X-Rate-Limit-Remaining")).isNotNull();
        }
    }

    @Nested
    @DisplayName("User endpoint via HTTP")
    class UserEndpoint {

        @Test
        @DisplayName("/api/data returns 401 without credentials")
        void dataReturns401WithoutCredentials() {
            var response = restTemplate.getForEntity("/api/data", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("/api/data returns 200 with valid user credentials")
        void dataReturns200WithUserCredentials() {
            var response = restTemplate
                    .withBasicAuth("user", "user")
                    .getForEntity("/api/data", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("user-data");
        }

        @Test
        @DisplayName("/api/data response carries X-Rate-Limit-Remaining header")
        void dataHasRateLimitHeader() {
            var response = restTemplate
                    .withBasicAuth("user", "user")
                    .getForEntity("/api/data", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst("X-Rate-Limit-Remaining")).isNotNull();
        }
    }

    @Nested
    @DisplayName("Admin endpoint via HTTP")
    class AdminEndpoint {

        @Test
        @DisplayName("/api/admin/settings returns 401 without credentials")
        void adminSettingsReturns401WithoutCredentials() {
            var response = restTemplate.getForEntity("/api/admin/settings", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("/api/admin/settings returns 403 for user role")
        void adminSettingsReturns403ForUser() {
            var response = restTemplate
                    .withBasicAuth("user", "user")
                    .getForEntity("/api/admin/settings", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }

        @Test
        @DisplayName("/api/admin/settings returns 200 for admin role")
        void adminSettingsReturns200ForAdmin() {
            var response = restTemplate
                    .withBasicAuth("admin", "admin")
                    .getForEntity("/api/admin/settings", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("admin-settings");
        }

        @Test
        @DisplayName("/api/admin/settings response carries X-Rate-Limit-Remaining header")
        void adminSettingsHasRateLimitHeader() {
            var response = restTemplate
                    .withBasicAuth("admin", "admin")
                    .getForEntity("/api/admin/settings", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst("X-Rate-Limit-Remaining")).isNotNull();
        }

        @Test
        @DisplayName("/api/admin/audit returns 200 for admin role")
        void adminAuditReturns200ForAdmin() {
            var response = restTemplate
                    .withBasicAuth("admin", "admin")
                    .getForEntity("/api/admin/audit", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("audit-log");
        }
    }
}
