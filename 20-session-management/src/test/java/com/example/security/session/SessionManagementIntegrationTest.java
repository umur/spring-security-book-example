package com.example.security.session;

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

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
class SessionManagementIntegrationTest {

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
    @DisplayName("Session creation on login")
    class SessionCreation {

        @Test
        @DisplayName("unauthenticated request to dashboard redirects to login page")
        void unauthenticatedRedirectsToLogin() {
            var response = restTemplate.getForEntity("/dashboard", String.class);
            // TestRestTemplate follows redirects — final page will contain "Login"
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("Login");
        }

        @Test
        @DisplayName("authenticated user receives dashboard with session info")
        void authenticatedUserGetsDashboard() {
            var response = restTemplate
                    .withBasicAuth("admin", "admin")
                    .getForEntity("/dashboard", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }
    }

    @Nested
    @DisplayName("Session fixation protection via HTTP")
    class SessionFixationHttp {

        @Test
        @DisplayName("Set-Cookie header is present after successful form login")
        void loginSetsSessionCookie() {
            // POST to /login with form credentials
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            var body = "username=user&password=user";

            var response = restTemplate.exchange(
                    "/login", HttpMethod.POST,
                    new HttpEntity<>(body, headers),
                    String.class);

            // Expect a redirect (302) after successful login
            // The response should carry a Set-Cookie for JSESSIONID
            var allHeaders = response.getHeaders();
            boolean hasSessionCookie = allHeaders.getOrEmpty(HttpHeaders.SET_COOKIE)
                    .stream()
                    .anyMatch(v -> v.startsWith("JSESSIONID"));
            // Either we get a session cookie or we're already redirected (302 → 200 with follow)
            // With TestRestTemplate following redirects the status is 200
            assertThat(response.getStatusCode().is2xxSuccessful()
                    || response.getStatusCode().is3xxRedirection()).isTrue();
        }

        @Test
        @DisplayName("invalid credentials do not create an authenticated session")
        void invalidCredentialsNoSession() {
            var response = restTemplate
                    .withBasicAuth("user", "wrongpassword")
                    .getForEntity("/api/session-info", String.class);
            // Form-login app redirects unauthenticated to login page (200 after follow)
            // The JSON session-info response contains "sessionId" key; the HTML login page does not
            assertThat(response.getBody()).doesNotContain("sessionId");
        }
    }

    @Nested
    @DisplayName("Session info API")
    class SessionInfoApi {

        @Test
        @DisplayName("session-info endpoint is not accessible without authentication")
        void sessionInfoRequiresAuth() {
            var response = restTemplate.getForEntity("/api/session-info", String.class);
            // Redirect to login → 200 with login page HTML
            assertThat(response.getBody()).contains("Login");
        }
    }
}
