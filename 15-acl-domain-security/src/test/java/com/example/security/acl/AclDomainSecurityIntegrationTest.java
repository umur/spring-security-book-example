package com.example.security.acl;

import com.example.security.acl.controller.DocumentController.CreateDocumentRequest;
import com.example.security.acl.controller.DocumentController.GrantPermissionRequest;
import com.example.security.acl.dto.DocumentResponse;
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
class AclDomainSecurityIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17-alpine");

    @DynamicPropertySource
    static void configureDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
        // Disable H2 console when using postgres
        registry.add("spring.h2.console.enabled", () -> "false");
        // Use PostgreSQL-compatible ACL schema
        registry.add("spring.sql.init.schema-locations", () -> "classpath:acl-schema-pg.sql");
        // PostgreSQL identity queries — named sequences use currval()
        registry.add("acl.class-identity-query", () -> "SELECT currval('acl_class_sequence')");
        registry.add("acl.sid-identity-query", () -> "SELECT currval('acl_sid_sequence')");
    }

    @Autowired TestRestTemplate restTemplate;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private DocumentResponse createAs(String user, String pass, String title) {
        ResponseEntity<DocumentResponse> r = restTemplate
                .withBasicAuth(user, pass)
                .postForEntity("/api/documents",
                        new CreateDocumentRequest(title, "content"),
                        DocumentResponse.class);
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        return r.getBody();
    }

    private void grantPermission(String user, String pass, long docId,
                                  String targetUser, String permission) {
        ResponseEntity<Void> r = restTemplate
                .withBasicAuth(user, pass)
                .exchange("/api/documents/" + docId + "/permissions",
                        HttpMethod.PUT,
                        new HttpEntity<>(new GrantPermissionRequest(targetUser, permission)),
                        Void.class);
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    // -----------------------------------------------------------------------
    // Unauthenticated
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Unauthenticated access")
    class Unauthenticated {

        @Test
        @DisplayName("GET /api/documents without credentials returns 401")
        void unauthenticated() {
            ResponseEntity<String> r = restTemplate.getForEntity("/api/documents", String.class);
            assertThat(r.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    // -----------------------------------------------------------------------
    // Owner can read their own document
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Owner permissions (integration)")
    class OwnerPermissionsIT {

        @Test
        @DisplayName("Owner can read their document via HTTP Basic")
        void ownerCanRead() {
            DocumentResponse doc = createAs("alice", "alice", "Alice IT Private");

            ResponseEntity<DocumentResponse> r = restTemplate
                    .withBasicAuth("alice", "alice")
                    .getForEntity("/api/documents/" + doc.id(), DocumentResponse.class);

            assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(r.getBody().owner()).isEqualTo("alice");
        }
    }

    // -----------------------------------------------------------------------
    // Non-owner without permission gets 403
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Non-owner without permission (integration)")
    class NonOwnerIT {

        @Test
        @DisplayName("Non-owner without ACL entry is denied — 403")
        void nonOwnerDenied() {
            DocumentResponse doc = createAs("alice", "alice", "Alice IT Only");

            ResponseEntity<String> r = restTemplate
                    .withBasicAuth("bob", "bob")
                    .getForEntity("/api/documents/" + doc.id(), String.class);

            assertThat(r.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }
    }

    // -----------------------------------------------------------------------
    // After granting READ, non-owner can read
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Permission grant workflow (integration)")
    class GrantWorkflowIT {

        @Test
        @DisplayName("After granting READ, previously-denied user can access document")
        void afterGrantCanRead() {
            DocumentResponse doc = createAs("alice", "alice", "Alice Grant IT");
            grantPermission("alice", "alice", doc.id(), "charlie", "READ");

            ResponseEntity<DocumentResponse> r = restTemplate
                    .withBasicAuth("charlie", "charlie")
                    .getForEntity("/api/documents/" + doc.id(), DocumentResponse.class);

            assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(r.getBody().owner()).isEqualTo("alice");
        }

        @Test
        @DisplayName("Owner can grant READ and grantee sees document in list")
        void granteeSeesDocInList() {
            DocumentResponse doc = createAs("alice", "alice", "Alice Shared IT");
            grantPermission("alice", "alice", doc.id(), "bob", "READ");

            ResponseEntity<DocumentResponse[]> r = restTemplate
                    .withBasicAuth("bob", "bob")
                    .getForEntity("/api/documents", DocumentResponse[].class);

            assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(r.getBody()).anyMatch(d -> d.id().equals(doc.id()));
        }
    }

    // -----------------------------------------------------------------------
    // ADMIN can manage all documents
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("ADMIN privileges (integration)")
    class AdminIT {

        @Test
        @DisplayName("ADMIN can read any document regardless of ACL")
        void adminReadsAny() {
            DocumentResponse doc = createAs("alice", "alice", "Admin IT Reads");

            ResponseEntity<DocumentResponse> r = restTemplate
                    .withBasicAuth("admin", "admin")
                    .getForEntity("/api/documents/" + doc.id(), DocumentResponse.class);

            assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(r.getBody().owner()).isEqualTo("alice");
        }

        @Test
        @DisplayName("ADMIN can grant permission on any document")
        void adminCanGrant() {
            DocumentResponse doc = createAs("alice", "alice", "Admin Grant IT");
            grantPermission("admin", "admin", doc.id(), "bob", "READ");

            ResponseEntity<DocumentResponse> r = restTemplate
                    .withBasicAuth("bob", "bob")
                    .getForEntity("/api/documents/" + doc.id(), DocumentResponse.class);

            assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
        }
    }
}
