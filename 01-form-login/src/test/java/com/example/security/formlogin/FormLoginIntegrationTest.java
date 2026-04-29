package com.example.security.formlogin;

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
class FormLoginIntegrationTest {

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
    @DisplayName("Authentication flow")
    class AuthenticationFlow {

        @Test
        @DisplayName("unauthenticated request to protected resource returns login page")
        void unauthenticatedRedirectsToLogin() {
            var response = restTemplate.getForEntity("/dashboard", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("Login");
        }

        @Test
        @DisplayName("login with valid credentials succeeds")
        void loginWithValidCredentials() {
            var response = restTemplate
                    .withBasicAuth("admin", "admin")
                    .getForEntity("/dashboard", String.class);
            // TestRestTemplate follows redirects, so we get the final page
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        @Test
        @DisplayName("login with invalid credentials fails")
        void loginWithInvalidCredentials() {
            var response = restTemplate
                    .withBasicAuth("admin", "wrong")
                    .getForEntity("/dashboard", String.class);
            assertThat(response.getBody()).contains("Login");
        }
    }

    @Nested
    @DisplayName("Public resources")
    class PublicResources {

        @Test
        @DisplayName("login page is accessible without authentication")
        void loginPageAccessible() {
            var response = restTemplate.getForEntity("/login", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("Login");
        }
    }
}
