package com.example.security.rememberme;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.http.client.HttpRedirects;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
class RememberMeIntegrationTest {

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
    @DisplayName("Public endpoints")
    class PublicEndpoints {

        @Test
        @DisplayName("login page is accessible without authentication")
        void loginPageAccessible() {
            ResponseEntity<String> response = restTemplate.getForEntity("/login", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("Login");
        }

        @Test
        @DisplayName("unauthenticated access to dashboard redirects to login")
        void unauthenticatedRedirectsToLogin() {
            // TestRestTemplate follows redirects — final page is the login page
            ResponseEntity<String> response = restTemplate.getForEntity("/dashboard", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("Login");
        }
    }

    @Nested
    @DisplayName("Remember-me token behaviour")
    class RememberMeTokenBehaviour {

        /**
         * Posts to /login with remember-me=on using a non-redirect-following client
         * so we can inspect the Set-Cookie headers on the 302 response directly.
         */
        @Test
        @DisplayName("login with remember-me checkbox sets remember-me cookie in response")
        void loginWithRememberMeSetsCookie() {
            ResponseEntity<String> loginResponse = doLogin("user", "user", true);

            List<String> setCookies = loginResponse.getHeaders().get(HttpHeaders.SET_COOKIE);
            boolean hasRememberMe = setCookies != null &&
                    setCookies.stream().anyMatch(c -> c.startsWith("remember-me"));
            assertThat(hasRememberMe)
                    .as("Expected a remember-me Set-Cookie header in the login response")
                    .isTrue();
        }

        @Test
        @DisplayName("login without remember-me checkbox does not set remember-me cookie")
        void loginWithoutRememberMeDoesNotSetCookie() {
            ResponseEntity<String> loginResponse = doLogin("user", "user", false);

            List<String> setCookies = loginResponse.getHeaders().get(HttpHeaders.SET_COOKIE);
            boolean hasRememberMe = setCookies != null &&
                    setCookies.stream().anyMatch(c -> c.startsWith("remember-me"));
            assertThat(hasRememberMe)
                    .as("Did not expect a remember-me Set-Cookie header when remember-me was not requested")
                    .isFalse();
        }

        // --- helpers ---

        /**
         * Performs a form login POST without following redirects, so Set-Cookie headers
         * on the 302 are visible to the caller.
         */
        private ResponseEntity<String> doLogin(String username, String password, boolean rememberMe) {
            // Use a non-redirect-following client to observe the raw 302 response
            TestRestTemplate noRedirect = restTemplate.withRedirects(HttpRedirects.DONT_FOLLOW);

            // First GET /login to obtain a session cookie and CSRF token
            ResponseEntity<String> loginPage = noRedirect.getForEntity("/login", String.class);
            String sessionCookie = extractSessionCookie(loginPage.getHeaders().get(HttpHeaders.SET_COOKIE));
            String csrfToken = extractCsrfToken(loginPage.getBody());

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            if (sessionCookie != null) {
                headers.add(HttpHeaders.COOKIE, sessionCookie);
            }

            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("username", username);
            form.add("password", password);
            if (rememberMe) {
                form.add("remember-me", "on");
            }
            if (csrfToken != null) {
                form.add("_csrf", csrfToken);
            }

            return noRedirect.exchange(
                    "/login", HttpMethod.POST,
                    new HttpEntity<>(form, headers),
                    String.class
            );
        }

        private String extractSessionCookie(List<String> setCookieHeaders) {
            if (setCookieHeaders == null) return null;
            return setCookieHeaders.stream()
                    .filter(c -> c.startsWith("JSESSIONID"))
                    .map(c -> c.split(";")[0])
                    .findFirst()
                    .orElse(null);
        }

        private String extractCsrfToken(String html) {
            if (html == null) return null;
            int idx = html.indexOf("name=\"_csrf\"");
            if (idx == -1) return null;
            int valueIdx = html.indexOf("value=\"", idx);
            if (valueIdx == -1) return null;
            int start = valueIdx + 7;
            int end = html.indexOf("\"", start);
            if (end == -1) return null;
            return html.substring(start, end);
        }
    }
}
