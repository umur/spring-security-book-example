package com.example.security.auditing;

import com.example.security.auditing.repository.AuditEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
class AuditingIntegrationTest {

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
    }

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @BeforeEach
    void clearAuditLog() {
        auditEventRepository.deleteAll();
    }

    @Nested
    @DisplayName("Authentication event recording")
    class AuthenticationEvents {

        @Test
        @DisplayName("successful login creates an AUTH_SUCCESS audit event")
        void successfulLoginCreatesAuditEvent() {
            restTemplate.withBasicAuth("user", "user")
                    .getForEntity("/api/profile", String.class);

            var events = auditEventRepository.findByUsernameOrderByTimestampDesc("user");
            assertThat(events).isNotEmpty();
            boolean hasSuccess = events.stream()
                    .anyMatch(e -> "AUTH_SUCCESS".equals(e.getEventType()));
            assertThat(hasSuccess).isTrue();
        }

        @Test
        @DisplayName("failed login creates an AUTH_FAILURE audit event")
        void failedLoginCreatesAuditEvent() {
            restTemplate.withBasicAuth("user", "wrongpassword")
                    .getForEntity("/api/profile", String.class);

            var events = auditEventRepository.findByUsernameOrderByTimestampDesc("user");
            assertThat(events).isNotEmpty();
            boolean hasFailure = events.stream()
                    .anyMatch(e -> "AUTH_FAILURE".equals(e.getEventType()));
            assertThat(hasFailure).isTrue();
        }
    }

    @Nested
    @DisplayName("Audit log endpoint")
    class AuditLogEndpoint {

        @Test
        @DisplayName("ADMIN can retrieve audit events via GET /api/audit-log")
        void adminCanRetrieveAuditEvents() {
            // Generate some events first
            restTemplate.withBasicAuth("user", "user")
                    .getForEntity("/api/profile", String.class);

            var response = restTemplate.withBasicAuth("admin", "admin")
                    .getForEntity("/api/audit-log", String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
        }

        @Test
        @DisplayName("unauthenticated request to /api/audit-log returns 401")
        void unauthenticatedAuditLogReturns401() {
            var response = restTemplate.getForEntity("/api/audit-log", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("USER role gets 403 on /api/audit-log")
        void userRoleGetsForbiddenOnAuditLog() {
            var response = restTemplate.withBasicAuth("user", "user")
                    .getForEntity("/api/audit-log", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }
    }
}
