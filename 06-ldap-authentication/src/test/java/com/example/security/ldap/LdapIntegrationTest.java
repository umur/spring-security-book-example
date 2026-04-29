package com.example.security.ldap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for LDAP authentication using the embedded UnboundID LDAP server.
 * All tests share a single ApplicationContext to avoid port conflicts from context recreation.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
class LdapIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    @DisplayName("valid user credentials -> 200 on GET /api/profile")
    void validUserCredentialsReturn200() {
        var response = restTemplate
                .withBasicAuth("user", "user")
                .getForEntity("/api/profile", String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("user");
    }

    @Test
    @DisplayName("valid admin credentials -> 200 on GET /api/profile")
    void validAdminCredentialsReturn200() {
        var response = restTemplate
                .withBasicAuth("admin", "admin")
                .getForEntity("/api/profile", String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("admin");
    }

    @Test
    @DisplayName("invalid credentials -> 401")
    void invalidCredentialsReturn401() {
        var response = restTemplate
                .withBasicAuth("user", "wrongpassword")
                .getForEntity("/api/profile", String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("unauthenticated -> 401")
    void unauthenticatedReturns401() {
        var response = restTemplate.getForEntity("/api/profile", String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("admin user has ROLE_ADMIN -> can access /api/admin")
    void adminUserCanAccessAdminEndpoint() {
        var response = restTemplate
                .withBasicAuth("admin", "admin")
                .getForEntity("/api/admin", String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("Admin area");
    }

    @Test
    @DisplayName("regular user does not have ROLE_ADMIN -> 403 on /api/admin")
    void regularUserCannotAccessAdminEndpoint() {
        var response = restTemplate
                .withBasicAuth("user", "user")
                .getForEntity("/api/admin", String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    @DisplayName("admin profile includes ROLE_ADMIN in roles")
    void adminProfileContainsAdminRole() {
        var response = restTemplate
                .withBasicAuth("admin", "admin")
                .getForEntity("/api/profile", String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("ROLE_ADMIN");
    }
}
