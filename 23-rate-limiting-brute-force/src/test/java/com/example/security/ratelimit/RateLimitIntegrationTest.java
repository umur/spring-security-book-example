package com.example.security.ratelimit;

import com.example.security.ratelimit.service.LoginAttemptService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
class RateLimitIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17-alpine");

    @DynamicPropertySource
    static void configureDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
        registry.add("spring.jpa.database-platform", () -> "org.hibernate.dialect.PostgreSQLDialect");
        registry.add("app.security.max-attempts", () -> "3");
        registry.add("app.security.lock-duration-seconds", () -> "5");
    }

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @BeforeEach
    void resetAttempts() {
        loginAttemptService.reset();
    }

    private org.springframework.http.ResponseEntity<String> doLogin(String username, String password) {
        var headers = new org.springframework.http.HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        String body = """
                {"username":"%s","password":"%s"}
                """.formatted(username, password);
        return restTemplate.postForEntity("/api/auth/login",
                new org.springframework.http.HttpEntity<>(body, headers),
                String.class);
    }

    @Nested
    @DisplayName("Login attempt tracking")
    class LoginAttempts {

        @Test
        @DisplayName("valid credentials return 200 OK")
        void validCredentialsReturn200() {
            var response = doLogin("user", "user");
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("Login successful");
        }

        @Test
        @DisplayName("invalid credentials return 401 Unauthorized")
        void invalidCredentialsReturn401() {
            var response = doLogin("user", "wrongpassword");
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("account is locked after max failed attempts and returns 423")
        void accountLockedAfterMaxAttempts() {
            // max-attempts=3 via DynamicPropertySource
            doLogin("user", "wrong");
            doLogin("user", "wrong");
            doLogin("user", "wrong");

            var response = doLogin("user", "wrong");
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.LOCKED);
        }

        @Test
        @DisplayName("locked account returns 423 even with correct password")
        void lockedAccountRejectsCorrectPassword() {
            doLogin("user", "wrong");
            doLogin("user", "wrong");
            doLogin("user", "wrong");

            var response = doLogin("user", "user");
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.LOCKED);
        }

        @Test
        @DisplayName("account auto-unlocks after lock duration expires")
        void accountAutoUnlocksAfterTimeout() throws InterruptedException {
            // Lock the account by forcing a past lock time (2 seconds ago, lock duration=5s)
            loginAttemptService.forceLock("user", Instant.now().minusSeconds(6));

            // Should be unlocked now
            var response = doLogin("user", "user");
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        @Test
        @DisplayName("different usernames are tracked independently")
        void differentUsernamesTrackedIndependently() {
            // Lock user
            doLogin("user", "wrong");
            doLogin("user", "wrong");
            doLogin("user", "wrong");

            // admin should still be able to log in
            var adminResponse = doLogin("admin", "admin");
            assertThat(adminResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

            // user should be locked
            var userResponse = doLogin("user", "user");
            assertThat(userResponse.getStatusCode()).isEqualTo(HttpStatus.LOCKED);
        }

        @Test
        @DisplayName("successful login clears failed attempt counter")
        void successfulLoginClearsAttemptCounter() {
            doLogin("user", "wrong");
            doLogin("user", "wrong");

            // Correct password — resets counter
            var okResponse = doLogin("user", "user");
            assertThat(okResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

            // Now two more wrong attempts should not lock (counter was reset)
            doLogin("user", "wrong");
            doLogin("user", "wrong");
            var stillOk = doLogin("user", "user");
            assertThat(stillOk.getStatusCode()).isEqualTo(HttpStatus.OK);
        }
    }

    @Nested
    @DisplayName("Protected data endpoint via HTTP Basic")
    class ProtectedData {

        @Test
        @DisplayName("authenticated user can access /api/data via HTTP Basic")
        void authenticatedUserCanAccessData() {
            var response = restTemplate.withBasicAuth("user", "user")
                    .getForEntity("/api/data", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("Protected data");
        }

        @Test
        @DisplayName("unauthenticated request to /api/data returns 401")
        void unauthenticatedDataReturns401() {
            var response = restTemplate.getForEntity("/api/data", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    @Nested
    @DisplayName("Account status endpoint")
    class AccountStatus {

        @Test
        @DisplayName("ADMIN can view account status")
        void adminCanViewAccountStatus() {
            var response = restTemplate.withBasicAuth("admin", "admin")
                    .getForEntity("/api/account/status?username=user", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("\"locked\"");
        }
    }
}
