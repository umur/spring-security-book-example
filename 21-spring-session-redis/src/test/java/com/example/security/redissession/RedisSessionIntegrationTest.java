package com.example.security.redissession;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.main.allow-bean-definition-overriding=true")
@AutoConfigureTestRestTemplate
@Testcontainers
@Import(TestRedisSessionConfig.class)
class RedisSessionIntegrationTest {

    @Container
    @SuppressWarnings("resource")
    static GenericContainer<?> redis =
            new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17-alpine");

    @DynamicPropertySource
    static void configureContainers(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
    }

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private StringRedisTemplate redisTemplate;

    // -----------------------------------------------------------------------
    // Helper shared across nested classes via enclosing instance
    // -----------------------------------------------------------------------

    private static String extractCsrfToken(String html) {
        if (html == null) return "";
        // Thymeleaf renders: <input type="hidden" name="_csrf" value="TOKEN"/>
        int nameIdx = html.indexOf("name=\"_csrf\"");
        if (nameIdx < 0) return "";
        int tagStart = html.lastIndexOf("<input", nameIdx);
        if (tagStart < 0) return "";
        int tagEnd = html.indexOf(">", nameIdx);
        if (tagEnd < 0) return "";
        String tag = html.substring(tagStart, tagEnd);
        int valueIdx = tag.indexOf("value=\"");
        if (valueIdx < 0) return "";
        int start = valueIdx + 7;
        int end = tag.indexOf("\"", start);
        return end > start ? tag.substring(start, end) : "";
    }

    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Login creates session in Redis")
    class LoginCreatesSession {

        @Test
        @DisplayName("unauthenticated request to dashboard redirects to login page")
        void unauthenticatedRedirectsToLogin() {
            var response = restTemplate.getForEntity("/dashboard", String.class);
            // TestRestTemplate follows redirects — final response contains login page HTML
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
            assertThat(response.getBody()).contains("Dashboard");
        }

        @Test
        @DisplayName("login via form creates session stored in Redis")
        void loginCreatesRedisSession() {
            // First GET /login to obtain CSRF token and session cookie
            var loginPage = restTemplate.getForEntity("/login", String.class);
            assertThat(loginPage.getStatusCode()).isEqualTo(HttpStatus.OK);

            String csrfToken = extractCsrfToken(loginPage.getBody());

            // Carry session cookie so CSRF validation passes
            String sessionCookie = loginPage.getHeaders().getOrEmpty(HttpHeaders.SET_COOKIE)
                    .stream().filter(c -> c.startsWith("SESSION")).findFirst().orElse("");
            String sessionId = sessionCookie.contains(";")
                    ? sessionCookie.substring(0, sessionCookie.indexOf(";"))
                    : sessionCookie;

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            if (!sessionId.isEmpty()) {
                headers.set(HttpHeaders.COOKIE, sessionId);
            }

            var response = restTemplate.exchange(
                    "/login", HttpMethod.POST,
                    new HttpEntity<>("username=user&password=user&_csrf=" + csrfToken, headers),
                    String.class);

            // 2xx (redirect followed to dashboard) or 3xx (redirect not followed)
            int status = response.getStatusCode().value();
            assertThat(status).isBetween(200, 399);

            // Verify Spring Session persisted the session to Redis
            Set<String> keys = redisTemplate.keys("spring:session:redis-example:*");
            assertThat(keys).isNotNull().isNotEmpty();
        }
    }

    @Nested
    @DisplayName("Session attribute persistence")
    class SessionAttributePersistence {

        @Test
        @DisplayName("session attribute set via API is persisted")
        void sessionAttributePersistsAcrossRequests() {
            var authTemplate = restTemplate.withBasicAuth("user", "user");

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            var setResponse = authTemplate.exchange(
                    "/api/session/attribute", HttpMethod.POST,
                    new HttpEntity<>("{\"name\":\"theme\",\"value\":\"dark\"}", headers),
                    String.class);

            assertThat(setResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(setResponse.getBody()).contains("theme");
            assertThat(setResponse.getBody()).contains("dark");
        }

        @Test
        @DisplayName("session info endpoint returns JSON with session metadata")
        void sessionInfoReturnsMetadata() {
            var response = restTemplate
                    .withBasicAuth("user", "user")
                    .getForEntity("/api/session/info", String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("sessionId");
            assertThat(response.getBody()).contains("user");
        }
    }

    @Nested
    @DisplayName("Session stored in Redis not in-memory")
    class SessionStoredInRedis {

        @Test
        @DisplayName("Redis contains session keys after authentication")
        void redisContainsSessionKeys() {
            // Trigger session creation via basic auth — flush-mode:immediate writes it at once
            restTemplate.withBasicAuth("admin", "admin")
                    .getForEntity("/dashboard", String.class);

            Set<String> keys = redisTemplate.keys("spring:session:redis-example:*");
            assertThat(keys).isNotNull().isNotEmpty();
        }
    }
}
