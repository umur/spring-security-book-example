package com.example.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
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

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
class JwtIntegrationTest {

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

    private final ObjectMapper objectMapper = new ObjectMapper();

    private HttpHeaders jsonHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    private String loginAndGetAccessToken(String username, String password) throws Exception {
        String body = """
                {"username":"%s","password":"%s"}
                """.formatted(username, password);
        ResponseEntity<String> response = restTemplate.postForEntity(
                "/api/auth/login",
                new HttpEntity<>(body, jsonHeaders()),
                String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        return objectMapper.readTree(response.getBody()).get("accessToken").asText();
    }

    private String loginAndGetRefreshToken(String username, String password) throws Exception {
        String body = """
                {"username":"%s","password":"%s"}
                """.formatted(username, password);
        ResponseEntity<String> response = restTemplate.postForEntity(
                "/api/auth/login",
                new HttpEntity<>(body, jsonHeaders()),
                String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        return objectMapper.readTree(response.getBody()).get("refreshToken").asText();
    }

    @Nested
    @DisplayName("Login flow")
    class LoginFlow {

        @Test
        @DisplayName("Valid user credentials return access and refresh tokens")
        void validCredentialsReturnTokens() throws Exception {
            String body = """
                    {"username":"user","password":"user"}
                    """;
            ResponseEntity<String> response = restTemplate.postForEntity(
                    "/api/auth/login",
                    new HttpEntity<>(body, jsonHeaders()),
                    String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            var json = objectMapper.readTree(response.getBody());
            assertThat(json.get("accessToken").asText()).isNotBlank();
            assertThat(json.get("refreshToken").asText()).isNotBlank();
            assertThat(json.get("tokenType").asText()).isEqualTo("Bearer");
        }

        @Test
        @DisplayName("Invalid credentials are rejected with 401")
        void invalidCredentialsRejected() {
            String body = """
                    {"username":"user","password":"wrongpassword"}
                    """;
            ResponseEntity<String> response = restTemplate.postForEntity(
                    "/api/auth/login",
                    new HttpEntity<>(body, jsonHeaders()),
                    String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("Unknown user is rejected with 401")
        void unknownUserRejected() {
            String body = """
                    {"username":"nobody","password":"password"}
                    """;
            ResponseEntity<String> response = restTemplate.postForEntity(
                    "/api/auth/login",
                    new HttpEntity<>(body, jsonHeaders()),
                    String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    @Nested
    @DisplayName("Protected resource access")
    class ProtectedAccess {

        @Test
        @DisplayName("Full flow: login -> get token -> access protected GET /api/tasks")
        void fullLoginAndAccessFlow() throws Exception {
            String accessToken = loginAndGetAccessToken("user", "user");

            HttpHeaders authHeaders = new HttpHeaders();
            authHeaders.set("Authorization", "Bearer " + accessToken);

            ResponseEntity<String> tasksResponse = restTemplate.exchange(
                    "/api/tasks",
                    HttpMethod.GET,
                    new HttpEntity<>(authHeaders),
                    String.class);

            assertThat(tasksResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        @Test
        @DisplayName("Access protected endpoint without token returns 401")
        void withoutTokenReturns401() {
            ResponseEntity<String> response = restTemplate.getForEntity("/api/tasks", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("Full flow: login -> create task -> task appears in list")
        void createTaskAndRetrieve() throws Exception {
            String accessToken = loginAndGetAccessToken("admin", "admin");

            HttpHeaders authHeaders = new HttpHeaders();
            authHeaders.setContentType(MediaType.APPLICATION_JSON);
            authHeaders.set("Authorization", "Bearer " + accessToken);

            String taskBody = """
                    {"title":"Integration Task","description":"Created in integration test"}
                    """;
            ResponseEntity<String> createResponse = restTemplate.postForEntity(
                    "/api/tasks",
                    new HttpEntity<>(taskBody, authHeaders),
                    String.class);

            assertThat(createResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            var created = objectMapper.readTree(createResponse.getBody());
            assertThat(created.get("title").asText()).isEqualTo("Integration Task");
            assertThat(created.get("ownerUsername").asText()).isEqualTo("admin");

            HttpHeaders getHeaders = new HttpHeaders();
            getHeaders.set("Authorization", "Bearer " + accessToken);
            ResponseEntity<String> listResponse = restTemplate.exchange(
                    "/api/tasks",
                    HttpMethod.GET,
                    new HttpEntity<>(getHeaders),
                    String.class);

            assertThat(listResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(listResponse.getBody()).contains("Integration Task");
        }
    }

    @Nested
    @DisplayName("Refresh token flow")
    class RefreshTokenFlow {

        @Test
        @DisplayName("Valid refresh token returns new access and refresh tokens")
        void validRefreshTokenReturnsNewTokens() throws Exception {
            String refreshToken = loginAndGetRefreshToken("user", "user");

            String body = """
                    {"refreshToken":"%s"}
                    """.formatted(refreshToken);
            ResponseEntity<String> response = restTemplate.postForEntity(
                    "/api/auth/refresh",
                    new HttpEntity<>(body, jsonHeaders()),
                    String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            var json = objectMapper.readTree(response.getBody());
            assertThat(json.get("accessToken").asText()).isNotBlank();
            assertThat(json.get("refreshToken").asText()).isNotBlank();
        }

        @Test
        @DisplayName("New access token from refresh works on protected endpoint")
        void newAccessTokenFromRefreshWorks() throws Exception {
            String refreshToken = loginAndGetRefreshToken("user", "user");

            String refreshBody = """
                    {"refreshToken":"%s"}
                    """.formatted(refreshToken);
            ResponseEntity<String> refreshResponse = restTemplate.postForEntity(
                    "/api/auth/refresh",
                    new HttpEntity<>(refreshBody, jsonHeaders()),
                    String.class);

            assertThat(refreshResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            String newAccessToken = objectMapper.readTree(refreshResponse.getBody()).get("accessToken").asText();

            HttpHeaders authHeaders = new HttpHeaders();
            authHeaders.set("Authorization", "Bearer " + newAccessToken);

            ResponseEntity<String> tasksResponse = restTemplate.exchange(
                    "/api/tasks",
                    HttpMethod.GET,
                    new HttpEntity<>(authHeaders),
                    String.class);

            assertThat(tasksResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        @Test
        @DisplayName("Invalid refresh token returns 401")
        void invalidRefreshTokenReturns401() {
            String body = """
                    {"refreshToken":"this.is.not.valid"}
                    """;
            ResponseEntity<String> response = restTemplate.postForEntity(
                    "/api/auth/refresh",
                    new HttpEntity<>(body, jsonHeaders()),
                    String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }
}
