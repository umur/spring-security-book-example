package com.example.security.multitenancy;

import com.example.security.multitenancy.filter.TenantResolutionFilter;
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
class MultiTenancyIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17-alpine");

    @DynamicPropertySource
    static void configureDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> postgres.getJdbcUrl() + "?sslmode=disable");
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
        registry.add("spring.jpa.database-platform", () -> "org.hibernate.dialect.PostgreSQLDialect");
    }

    @Autowired
    private TestRestTemplate restTemplate;

    private HttpHeaders tenantHeaders(String tenantId) {
        var headers = new HttpHeaders();
        headers.set(TenantResolutionFilter.TENANT_HEADER, tenantId);
        return headers;
    }

    // -------------------------------------------------------------------------
    // Missing tenant header
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Missing tenant header")
    class MissingTenantHeaderIT {

        @Test
        @DisplayName("request without X-Tenant-ID returns 400")
        void missingHeaderReturns400() {
            var response = restTemplate.getForEntity("/api/data", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        }
    }

    // -------------------------------------------------------------------------
    // Tenant A — valid credentials
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Tenant A — HTTP Basic authentication")
    class TenantAAuthIT {

        @Test
        @DisplayName("tenant-a admin authenticates and fetches data — 200")
        void tenantAAdminFetchesData() {
            var headers = tenantHeaders("tenant-a");
            var response = restTemplate
                    .withBasicAuth("admin", "admin")
                    .exchange("/api/data", HttpMethod.GET, new HttpEntity<>(headers), String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("tenant-a");
        }

        @Test
        @DisplayName("tenant-a user authenticates and fetches tenant info — 200")
        void tenantAUserFetchesTenantInfo() {
            var headers = tenantHeaders("tenant-a");
            var response = restTemplate
                    .withBasicAuth("user", "user")
                    .exchange("/api/tenant/info", HttpMethod.GET, new HttpEntity<>(headers), String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("tenant-a");
            assertThat(response.getBody()).contains("user");
        }

        @Test
        @DisplayName("tenant-a user creates data — 201")
        void tenantAUserCreatesData() {
            var headers = tenantHeaders("tenant-a");
            headers.setContentType(MediaType.APPLICATION_JSON);
            var response = restTemplate
                    .withBasicAuth("user", "user")
                    .exchange("/api/data", HttpMethod.POST,
                            new HttpEntity<>("{\"content\":\"integration test record\"}", headers),
                            String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            assertThat(response.getBody()).contains("tenant-a");
            assertThat(response.getBody()).contains("integration test record");
        }

        @Test
        @DisplayName("wrong password for tenant-a returns 401")
        void wrongPasswordReturns401() {
            var headers = tenantHeaders("tenant-a");
            var response = restTemplate
                    .withBasicAuth("admin", "wrongpassword")
                    .exchange("/api/data", HttpMethod.GET, new HttpEntity<>(headers), String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    // -------------------------------------------------------------------------
    // Tenant B — valid credentials
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Tenant B — HTTP Basic authentication")
    class TenantBAuthIT {

        @Test
        @DisplayName("tenant-b bob authenticates and fetches data — 200")
        void tenantBBobFetchesData() {
            var headers = tenantHeaders("tenant-b");
            var response = restTemplate
                    .withBasicAuth("bob", "bob")
                    .exchange("/api/data", HttpMethod.GET, new HttpEntity<>(headers), String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("tenant-b");
        }

        @Test
        @DisplayName("tenant-b data does NOT contain tenant-a records")
        void tenantBDataExcludesTenantARecords() {
            var headers = tenantHeaders("tenant-b");
            var response = restTemplate
                    .withBasicAuth("bob", "bob")
                    .exchange("/api/data", HttpMethod.GET, new HttpEntity<>(headers), String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).doesNotContain("Tenant A");
        }
    }

    // -------------------------------------------------------------------------
    // Cross-tenant isolation
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Cross-tenant isolation")
    class CrossTenantIsolationIT {

        @Test
        @DisplayName("tenant-a credentials rejected in tenant-b context (user not found)")
        void tenantAUserRejectedInTenantBContext() {
            // "user" only exists in tenant-a, not tenant-b
            var headers = tenantHeaders("tenant-b");
            var response = restTemplate
                    .withBasicAuth("user", "user")
                    .exchange("/api/data", HttpMethod.GET, new HttpEntity<>(headers), String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("'admin' in tenant-a sees only tenant-a data")
        void adminInTenantASeesOnlyTenantAData() {
            var headers = tenantHeaders("tenant-a");
            var response = restTemplate
                    .withBasicAuth("admin", "admin")
                    .exchange("/api/data", HttpMethod.GET, new HttpEntity<>(headers), String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("Tenant A");
            assertThat(response.getBody()).doesNotContain("Tenant B");
        }

        @Test
        @DisplayName("'admin' in tenant-b sees only tenant-b data")
        void adminInTenantBSeesOnlyTenantBData() {
            var headers = tenantHeaders("tenant-b");
            var response = restTemplate
                    .withBasicAuth("admin", "admin")
                    .exchange("/api/data", HttpMethod.GET, new HttpEntity<>(headers), String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("Tenant B");
            assertThat(response.getBody()).doesNotContain("Tenant A");
        }
    }
}
