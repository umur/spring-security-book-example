package com.cinetrack;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for LDAP bind authentication against the embedded
 * UnboundID server.
 *
 * <p>The full Spring context starts: including {@link EmbeddedLdapConfig} : 
 * so every test exercises the real LDAP handshake, not a mock.
 *
 * <p>Uses {@link java.net.http.HttpClient} (JDK 11+) with manually constructed
 * {@code Authorization: Basic} headers. This avoids any Spring Boot test
 * infrastructure dependency and works identically across Spring Boot versions.
 *
 * <p>User/group fixture from {@code ldap-test-server.ldif}:
 * <ul>
 *   <li>alice: password {@code alice123}, groups: viewers + admins</li>
 *   <li>bob  : password {@code bob123},   groups: viewers only</li>
 * </ul>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class LdapAuthenticationTest {

    @LocalServerPort
    int port;

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    private HttpResponse<String> get(String path, String username, String password)
            throws Exception {
        String credentials = Base64.getEncoder()
                .encodeToString((username + ":" + password).getBytes());
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + path))
                .header("Authorization", "Basic " + credentials)
                .GET()
                .build();
        return HTTP.send(request, HttpResponse.BodyHandlers.ofString());
    }

    @Test
    @DisplayName("Alice with correct password → 200 on /api/movies")
    void alice_correctPassword_canAccessMovies() throws Exception {
        var response = get("/api/movies", "alice", "alice123");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("Inception");
    }

    @Test
    @DisplayName("Alice with wrong password → 401")
    void alice_wrongPassword_isUnauthorized() throws Exception {
        var response = get("/api/movies", "alice", "wrong-password");

        assertThat(response.statusCode()).isEqualTo(401);
    }

    @Test
    @DisplayName("Alice can access /api/admin/users (she is in cn=admins)")
    void alice_canAccessAdminEndpoint() throws Exception {
        var response = get("/api/admin/users", "alice", "alice123");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("alice");
    }

    @Test
    @DisplayName("Bob cannot access /api/admin/users (only viewers group) → 403")
    void bob_cannotAccessAdminEndpoint() throws Exception {
        var response = get("/api/admin/users", "bob", "bob123");

        assertThat(response.statusCode()).isEqualTo(403);
    }

    @Test
    @DisplayName("Unknown user → 401")
    void unknownUser_isUnauthorized() throws Exception {
        var response = get("/api/movies", "nobody", "secret");

        assertThat(response.statusCode()).isEqualTo(401);
    }
}
