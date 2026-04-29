package com.example.security.httpbasic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
class HttpBasicIntegrationTest {

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
    @DisplayName("Authentication with HTTP Basic")
    class AuthenticationFlow {

        @Test
        @DisplayName("admin with correct password gets 200 on GET /api/notes")
        void adminWithCorrectPasswordGets200() {
            var response = restTemplate
                    .withBasicAuth("admin", "admin")
                    .getForEntity("/api/notes", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        @Test
        @DisplayName("user with correct password gets 200 on GET /api/notes")
        void userWithCorrectPasswordGets200() {
            var response = restTemplate
                    .withBasicAuth("user", "user")
                    .getForEntity("/api/notes", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        @Test
        @DisplayName("wrong password returns 401")
        void wrongPasswordReturns401() {
            var response = restTemplate
                    .withBasicAuth("admin", "wrongpassword")
                    .getForEntity("/api/notes", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("unauthenticated request returns 401")
        void unauthenticatedReturns401() {
            var response = restTemplate.getForEntity("/api/notes", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    @Nested
    @DisplayName("Notes CRUD over HTTP Basic")
    class NotesCrud {

        @Test
        @DisplayName("admin can create a note and retrieve it")
        void adminCanCreateAndRetrieveNote() {
            // Create a note
            var createBody = """
                    {"title":"Integration Test Note","content":"Created by admin"}
                    """;
            var createResponse = restTemplate
                    .withBasicAuth("admin", "admin")
                    .postForEntity("/api/notes",
                            new org.springframework.http.HttpEntity<>(
                                    createBody,
                                    headersWithJson()),
                            String.class);
            assertThat(createResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            assertThat(createResponse.getBody()).contains("Integration Test Note");

            // Retrieve all notes - note should be present
            var listResponse = restTemplate
                    .withBasicAuth("admin", "admin")
                    .getForEntity("/api/notes", String.class);
            assertThat(listResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(listResponse.getBody()).contains("Integration Test Note");
        }

        @Test
        @DisplayName("response Content-Type is application/json")
        void responseContentTypeIsJson() {
            var response = restTemplate
                    .withBasicAuth("user", "user")
                    .getForEntity("/api/notes", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getContentType())
                    .isNotNull()
                    .satisfies(ct -> assertThat(ct.isCompatibleWith(MediaType.APPLICATION_JSON)).isTrue());
        }
    }

    private org.springframework.http.HttpHeaders headersWithJson() {
        var headers = new org.springframework.http.HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }
}
