package com.example.security.apikey;

import com.example.security.apikey.controller.ApiKeyController.GenerateKeyRequest;
import com.example.security.apikey.controller.ApiKeyController.GenerateKeyResponse;
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

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
class ApiKeyIntegrationTest {

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
    @DisplayName("Full lifecycle: generate -> use -> verify")
    class FullLifecycle {

        @Test
        @DisplayName("Admin generates USER key and uses it to access /api/data")
        void generateUserKeyAndAccessData() {
            // Step 1: generate API key via admin endpoint using HTTP Basic
            var generateResponse = restTemplate
                    .withBasicAuth("admin", "admin-secret")
                    .postForEntity("/api/keys", new GenerateKeyRequest("integration-client", "USER"), GenerateKeyResponse.class);

            assertThat(generateResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            assertThat(generateResponse.getBody()).isNotNull();
            String rawKey = generateResponse.getBody().apiKey();
            assertThat(rawKey).isNotBlank();

            // Step 2: use the raw key to access /api/data
            var dataResponse = restTemplate.exchange(
                    RequestEntity.get("/api/data")
                            .header("X-API-Key", rawKey)
                            .accept(MediaType.APPLICATION_JSON)
                            .build(),
                    String.class);

            assertThat(dataResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(dataResponse.getBody()).contains("integration-client");
        }

        @Test
        @DisplayName("USER-scoped key cannot access /api/data/admin — returns 403")
        void userKeyCannotAccessAdminEndpoint() {
            // Generate USER-scoped key
            var generateResponse = restTemplate
                    .withBasicAuth("admin", "admin-secret")
                    .postForEntity("/api/keys", new GenerateKeyRequest("user-client", "USER"), GenerateKeyResponse.class);

            assertThat(generateResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            String rawKey = generateResponse.getBody().apiKey();

            // Try admin endpoint — expect 403
            var adminResponse = restTemplate.exchange(
                    RequestEntity.get("/api/data/admin")
                            .header("X-API-Key", rawKey)
                            .build(),
                    String.class);

            assertThat(adminResponse.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }

        @Test
        @DisplayName("ADMIN-scoped key can access /api/data/admin — returns 200")
        void adminKeyCanAccessAdminEndpoint() {
            // Generate ADMIN-scoped key
            var generateResponse = restTemplate
                    .withBasicAuth("admin", "admin-secret")
                    .postForEntity("/api/keys", new GenerateKeyRequest("admin-client", "ADMIN"), GenerateKeyResponse.class);

            assertThat(generateResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            String rawKey = generateResponse.getBody().apiKey();

            // Access admin endpoint — expect 200
            var adminResponse = restTemplate.exchange(
                    RequestEntity.get("/api/data/admin")
                            .header("X-API-Key", rawKey)
                            .build(),
                    String.class);

            assertThat(adminResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(adminResponse.getBody()).contains("admin-client");
        }

        @Test
        @DisplayName("Invalid key returns 401 on /api/data")
        void invalidKeyReturns401() {
            var response = restTemplate.exchange(
                    RequestEntity.get("/api/data")
                            .header("X-API-Key", "invalid-key-that-does-not-exist")
                            .build(),
                    String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("No key returns 401 on /api/data")
        void noKeyReturns401() {
            var response = restTemplate.getForEntity("/api/data", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("Generating key without admin credentials returns 401")
        void generateKeyWithoutAdminCredentialsReturns401() {
            var response = restTemplate.postForEntity(
                    "/api/keys",
                    new GenerateKeyRequest("attacker", "ADMIN"),
                    String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }
}
