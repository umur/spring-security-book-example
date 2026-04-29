package com.example.security.methodsecurity;

import com.example.security.methodsecurity.controller.DocumentController.CreateDocumentRequest;
import com.example.security.methodsecurity.controller.DocumentController.DocumentResponse;
import com.example.security.methodsecurity.controller.DocumentController.UpdateDocumentRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
class MethodSecurityIntegrationTest {

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

    // ---------------------------------------------------------------------------
    // Helper: create a document as a given user
    // ---------------------------------------------------------------------------
    private DocumentResponse createAs(String username, String password, String title, String content) {
        ResponseEntity<DocumentResponse> response = restTemplate
                .withBasicAuth(username, password)
                .postForEntity("/api/documents",
                        new CreateDocumentRequest(title, content),
                        DocumentResponse.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        return response.getBody();
    }

    // ---------------------------------------------------------------------------
    // Unauthenticated
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("Unauthenticated access")
    class UnauthenticatedAccessIT {

        @Test
        @DisplayName("GET /api/documents without auth returns 401")
        void unauthenticatedReturns401() {
            ResponseEntity<String> response = restTemplate.getForEntity("/api/documents", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    // ---------------------------------------------------------------------------
    // PostFilter — listing documents
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("PostFilter — list documents")
    class PostFilterIT {

        @Test
        @DisplayName("USER sees only their own documents when listing")
        void userSeesOnlyOwnDocuments() {
            createAs("alice", "alice", "Alice IT Doc", "content A");
            createAs("bob", "bob", "Bob IT Doc", "content B");

            ResponseEntity<DocumentResponse[]> response = restTemplate
                    .withBasicAuth("alice", "alice")
                    .getForEntity("/api/documents", DocumentResponse[].class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).allMatch(d -> "alice".equals(d.owner()));
        }

        @Test
        @DisplayName("ADMIN sees all documents when listing")
        void adminSeesAllDocuments() {
            createAs("alice", "alice", "Alice IT Doc 2", "content A2");
            createAs("bob", "bob", "Bob IT Doc 2", "content B2");

            ResponseEntity<DocumentResponse[]> response = restTemplate
                    .withBasicAuth("admin", "admin")
                    .getForEntity("/api/documents", DocumentResponse[].class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();

            long distinctOwners = java.util.Arrays.stream(response.getBody())
                    .map(DocumentResponse::owner)
                    .distinct()
                    .count();
            assertThat(distinctOwners).isGreaterThan(1);
        }
    }

    // ---------------------------------------------------------------------------
    // PostAuthorize — get by id
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("PostAuthorize — get document by id")
    class PostAuthorizeIT {

        @Test
        @DisplayName("Owner can retrieve their document")
        void ownerCanRetrieveDocument() {
            DocumentResponse created = createAs("alice", "alice", "Alice Private", "secret");

            ResponseEntity<DocumentResponse> response = restTemplate
                    .withBasicAuth("alice", "alice")
                    .getForEntity("/api/documents/" + created.id(), DocumentResponse.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().owner()).isEqualTo("alice");
        }

        @Test
        @DisplayName("Non-owner USER is denied access to another user's document")
        void nonOwnerIsDenied() {
            DocumentResponse created = createAs("alice", "alice", "Alice Only", "private");

            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("bob", "bob")
                    .getForEntity("/api/documents/" + created.id(), String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }

        @Test
        @DisplayName("ADMIN can retrieve any user's document")
        void adminCanRetrieveAnyDocument() {
            DocumentResponse created = createAs("alice", "alice", "Alice Admin View", "content");

            ResponseEntity<DocumentResponse> response = restTemplate
                    .withBasicAuth("admin", "admin")
                    .getForEntity("/api/documents/" + created.id(), DocumentResponse.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody().owner()).isEqualTo("alice");
        }
    }

    // ---------------------------------------------------------------------------
    // PreAuthorize bean method — update
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("PreAuthorize bean method — update document")
    class PreAuthorizeBeanMethodIT {

        @Test
        @DisplayName("Owner can update their own document end-to-end")
        void ownerCanUpdate() {
            DocumentResponse created = createAs("alice", "alice", "Original Title", "original");

            ResponseEntity<DocumentResponse> response = restTemplate
                    .withBasicAuth("alice", "alice")
                    .exchange("/api/documents/" + created.id(),
                            HttpMethod.PUT,
                            new HttpEntity<>(new UpdateDocumentRequest("Updated Title", "updated content")),
                            DocumentResponse.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody().title()).isEqualTo("Updated Title");
        }

        @Test
        @DisplayName("Non-owner USER cannot update another user's document")
        void nonOwnerCannotUpdate() {
            DocumentResponse created = createAs("alice", "alice", "Alice's Doc", "content");

            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("bob", "bob")
                    .exchange("/api/documents/" + created.id(),
                            HttpMethod.PUT,
                            new HttpEntity<>(new UpdateDocumentRequest("Hijacked", "bad")),
                            String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }

        @Test
        @DisplayName("ADMIN can update any document")
        void adminCanUpdateAnyDocument() {
            DocumentResponse created = createAs("alice", "alice", "Alice Doc Admin", "original");

            ResponseEntity<DocumentResponse> response = restTemplate
                    .withBasicAuth("admin", "admin")
                    .exchange("/api/documents/" + created.id(),
                            HttpMethod.PUT,
                            new HttpEntity<>(new UpdateDocumentRequest("Admin Fixed", "fixed")),
                            DocumentResponse.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody().title()).isEqualTo("Admin Fixed");
        }
    }

    // ---------------------------------------------------------------------------
    // PreAuthorize hasRole — delete
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("PreAuthorize hasRole — delete document")
    class PreAuthorizeHasRoleIT {

        @Test
        @DisplayName("USER cannot delete a document")
        void userCannotDelete() {
            DocumentResponse created = createAs("alice", "alice", "Cant Delete", "content");

            ResponseEntity<String> response = restTemplate
                    .withBasicAuth("alice", "alice")
                    .exchange("/api/documents/" + created.id(),
                            HttpMethod.DELETE,
                            HttpEntity.EMPTY,
                            String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }

        @Test
        @DisplayName("ADMIN can delete any document end-to-end")
        void adminCanDelete() {
            DocumentResponse created = createAs("alice", "alice", "To Be Deleted", "temp");

            ResponseEntity<Void> deleteResponse = restTemplate
                    .withBasicAuth("admin", "admin")
                    .exchange("/api/documents/" + created.id(),
                            HttpMethod.DELETE,
                            HttpEntity.EMPTY,
                            Void.class);

            assertThat(deleteResponse.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

            // Verify it's gone — admin can't find it
            ResponseEntity<String> getResponse = restTemplate
                    .withBasicAuth("admin", "admin")
                    .getForEntity("/api/documents/" + created.id(), String.class);
            assertThat(getResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        }
    }
}
