package com.cinetrack.session;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies session lifecycle: creation on login, invalidation on logout.
 *
 * These tests drive the real form-login endpoint via a full embedded Tomcat
 * (RANDOM_PORT) so the actual session infrastructure is exercised. Because
 * the CSRF filter is active, we must supply the XSRF-TOKEN cookie and
 * X-XSRF-TOKEN header on every state-mutating POST.
 *
 * The CSRF token is obtained by first performing a GET to /login, which
 * triggers the CookieCsrfTokenRepository to set the XSRF-TOKEN cookie.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SessionManagementTest {

    @LocalServerPort
    int port;

    RestClient unauthenticated;

    @BeforeEach
    void setUp() {
        unauthenticated = RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .build();
    }

    // -----------------------------------------------------------------------
    // Helper: perform a form-login with the CSRF cookie dance.
    // Returns the Set-Cookie header from the login response.
    // -----------------------------------------------------------------------

    private ResponseEntity<Void> login(String username, String password) {
        // Step 1: GET /login to receive the XSRF-TOKEN cookie.
        ResponseEntity<String> loginPage = unauthenticated.get()
                .uri("/login")
                .retrieve()
                .onStatus(s -> true, (req, res) -> {})
                .toEntity(String.class);

        String csrfToken = extractCookieValue(loginPage.getHeaders().get("Set-Cookie"), "XSRF-TOKEN");
        String sessionCookie = extractCookieValue(loginPage.getHeaders().get("Set-Cookie"), "JSESSIONID");

        String cookieHeader = buildCookieHeader(sessionCookie, csrfToken);

        // Step 2: POST /login with the CSRF token.
        return unauthenticated.post()
                .uri("/login")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header("Cookie", cookieHeader)
                .header("X-XSRF-TOKEN", csrfToken != null ? csrfToken : "")
                .body("username=" + username + "&password=" + password)
                .retrieve()
                .onStatus(s -> true, (req, res) -> {})
                .toBodilessEntity();
    }

    // -----------------------------------------------------------------------
    // Successful login must issue a Set-Cookie header containing JSESSIONID.
    // -----------------------------------------------------------------------

    @Test
    void login_success_createsSession() {
        ResponseEntity<Void> response = login("alice", "password");

        List<String> cookies = response.getHeaders().get("Set-Cookie");
        assertThat(cookies).isNotNull();
        boolean hasSession = cookies.stream().anyMatch(c -> c.contains("JSESSIONID"));
        assertThat(hasSession)
                .as("A successful login must set a JSESSIONID cookie")
                .isTrue();
    }

    // -----------------------------------------------------------------------
    // A second login by the same user succeeds (maxSessionsPreventsLogin=false)
    // -----------------------------------------------------------------------

    @Test
    void login_secondSession_succeeds() {
        login("alice", "password");

        ResponseEntity<Void> second = login("alice", "password");
        List<String> cookies = second.getHeaders().get("Set-Cookie");
        assertThat(cookies).isNotNull();
        boolean hasSession = cookies.stream().anyMatch(c -> c.contains("JSESSIONID"));
        assertThat(hasSession)
                .as("A second login from the same user must also create a session")
                .isTrue();
    }

    // -----------------------------------------------------------------------
    // After logout the session must be invalidated.
    // -----------------------------------------------------------------------

    @Test
    void logout_invalidatesSession() {
        // Login and extract session ID.
        ResponseEntity<Void> loginResponse = login("alice", "password");
        List<String> loginCookies = loginResponse.getHeaders().get("Set-Cookie");
        assertThat(loginCookies).isNotNull();

        String sessionId = extractCookieValue(loginCookies, "JSESSIONID");
        String csrfToken = extractCookieValue(loginCookies, "XSRF-TOKEN");

        // If no fresh XSRF-TOKEN in login response, get one from a GET.
        if (csrfToken == null && sessionId != null) {
            ResponseEntity<Void> getMovies = unauthenticated.get()
                    .uri("/api/movies")
                    .header("Cookie", "JSESSIONID=" + sessionId)
                    .retrieve()
                    .onStatus(s -> true, (req, res) -> {})
                    .toBodilessEntity();
            List<String> getCookies = getMovies.getHeaders().get("Set-Cookie");
            if (getCookies != null) {
                csrfToken = extractCookieValue(getCookies, "XSRF-TOKEN");
            }
        }

        // Logout using the session.
        String cookieForLogout = buildCookieHeader(sessionId, csrfToken);
        ResponseEntity<Void> logoutResponse = unauthenticated.post()
                .uri("/logout")
                .header("Cookie", cookieForLogout)
                .header("X-XSRF-TOKEN", csrfToken != null ? csrfToken : "")
                .retrieve()
                .onStatus(s -> true, (req, res) -> {})
                .toBodilessEntity();

        // Logout redirects (302) or returns 200.
        assertThat(logoutResponse.getStatusCode().value()).isIn(200, 302);

        // Accessing /api/movies with the old session must not return 200.
        ResponseEntity<Void> afterLogout = unauthenticated.get()
                .uri("/api/movies")
                .header("Cookie", "JSESSIONID=" + sessionId)
                .retrieve()
                .onStatus(s -> true, (req, res) -> {})
                .toBodilessEntity();

        assertThat(afterLogout.getStatusCode().value())
                .as("After logout the old session must not grant access")
                .isNotEqualTo(200);
    }

    // -----------------------------------------------------------------------
    // Utilities
    // -----------------------------------------------------------------------

    private String extractCookieValue(List<String> setCookieHeaders, String name) {
        if (setCookieHeaders == null) return null;
        for (String header : setCookieHeaders) {
            for (String part : header.split(";")) {
                part = part.trim();
                if (part.startsWith(name + "=")) {
                    return part.substring(name.length() + 1);
                }
            }
        }
        return null;
    }

    private String buildCookieHeader(String sessionId, String csrfToken) {
        StringBuilder sb = new StringBuilder();
        if (sessionId != null) sb.append("JSESSIONID=").append(sessionId);
        if (csrfToken != null) {
            if (sb.length() > 0) sb.append("; ");
            sb.append("XSRF-TOKEN=").append(csrfToken);
        }
        return sb.toString();
    }
}
