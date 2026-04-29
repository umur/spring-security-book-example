package com.example.security.methodsecurity;

import com.example.security.methodsecurity.controller.DocumentController.DocumentResponse;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class MethodSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private static final String ALICE_DOC_JSON = """
            {"title":"Alice Doc","content":"Alice content"}
            """;

    private static final String BOB_DOC_JSON = """
            {"title":"Bob Doc","content":"Bob content"}
            """;

    // ---------------------------------------------------------------------------
    // Helper: create a document as a given user and return its id
    // ---------------------------------------------------------------------------
    private long createDocument(String username, String role, String json) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/documents")
                        .with(user(username).roles(role))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated())
                .andReturn();
        DocumentResponse response = objectMapper.readValue(
                result.getResponse().getContentAsString(), DocumentResponse.class);
        return response.id();
    }

    // ---------------------------------------------------------------------------
    // Unauthenticated
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("Unauthenticated access")
    class UnauthenticatedAccess {

        @Test
        @DisplayName("GET /api/documents without auth returns 401")
        void getDocumentsUnauthenticated() throws Exception {
            mockMvc.perform(get("/api/documents"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("POST /api/documents without auth returns 401")
        void postDocumentUnauthenticated() throws Exception {
            mockMvc.perform(post("/api/documents")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(ALICE_DOC_JSON))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("DELETE /api/documents/{id} without auth returns 401")
        void deleteDocumentUnauthenticated() throws Exception {
            mockMvc.perform(delete("/api/documents/1"))
                    .andExpect(status().isUnauthorized());
        }
    }

    // ---------------------------------------------------------------------------
    // Create document
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("Create document")
    class CreateDocument {

        @Test
        @DisplayName("Any authenticated USER can POST a document - returns 201")
        void userCanCreateDocument() throws Exception {
            mockMvc.perform(post("/api/documents")
                            .with(user("alice").roles("USER"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(ALICE_DOC_JSON))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.owner").value("alice"));
        }

        @Test
        @DisplayName("ADMIN can POST a document - returns 201")
        void adminCanCreateDocument() throws Exception {
            mockMvc.perform(post("/api/documents")
                            .with(user("admin").roles("ADMIN"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"title\":\"Admin Doc\",\"content\":\"content\"}"))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.owner").value("admin"));
        }
    }

    // ---------------------------------------------------------------------------
    // Get document by id — @PostAuthorize
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("Get document by id (@PostAuthorize)")
    class GetDocumentById {

        @Test
        @DisplayName("Owner can GET their own document - returns 200")
        void ownerCanGetOwnDocument() throws Exception {
            long id = createDocument("alice", "USER", ALICE_DOC_JSON);

            mockMvc.perform(get("/api/documents/" + id)
                            .with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.owner").value("alice"));
        }

        @Test
        @DisplayName("USER cannot GET another user's document - returns 403")
        void userCannotGetOtherUsersDocument() throws Exception {
            long id = createDocument("alice", "USER", ALICE_DOC_JSON);

            mockMvc.perform(get("/api/documents/" + id)
                            .with(user("bob").roles("USER")))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("ADMIN can GET any document - returns 200")
        void adminCanGetAnyDocument() throws Exception {
            long id = createDocument("alice", "USER", ALICE_DOC_JSON);

            mockMvc.perform(get("/api/documents/" + id)
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.owner").value("alice"));
        }
    }

    // ---------------------------------------------------------------------------
    // List documents — @PostFilter
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("List documents (@PostFilter)")
    class ListDocuments {

        @Test
        @DisplayName("GET /api/documents as USER returns only their own documents")
        void userSeesOnlyOwnDocuments() throws Exception {
            createDocument("alice", "USER", ALICE_DOC_JSON);
            createDocument("bob", "USER", BOB_DOC_JSON);

            MvcResult result = mockMvc.perform(get("/api/documents")
                            .with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andReturn();

            DocumentResponse[] docs = objectMapper.readValue(
                    result.getResponse().getContentAsString(), DocumentResponse[].class);

            assertThat(docs).allMatch(d -> "alice".equals(d.owner()));
        }

        @Test
        @DisplayName("GET /api/documents as ADMIN returns all documents")
        void adminSeesAllDocuments() throws Exception {
            createDocument("alice", "USER", ALICE_DOC_JSON);
            createDocument("bob", "USER", BOB_DOC_JSON);

            MvcResult result = mockMvc.perform(get("/api/documents")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andReturn();

            DocumentResponse[] docs = objectMapper.readValue(
                    result.getResponse().getContentAsString(), DocumentResponse[].class);

            // Admin should see documents from multiple owners (seeded + created above)
            long distinctOwners = java.util.Arrays.stream(docs)
                    .map(DocumentResponse::owner)
                    .distinct()
                    .count();
            assertThat(distinctOwners).isGreaterThan(1);
        }
    }

    // ---------------------------------------------------------------------------
    // Update document — @PreAuthorize via @documentSecurity bean
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("Update document (@PreAuthorize bean method)")
    class UpdateDocument {

        @Test
        @DisplayName("Owner can UPDATE their own document - returns 200")
        void ownerCanUpdateOwnDocument() throws Exception {
            long id = createDocument("alice", "USER", ALICE_DOC_JSON);

            mockMvc.perform(put("/api/documents/" + id)
                            .with(user("alice").roles("USER"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"title\":\"Updated\",\"content\":\"new content\"}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.title").value("Updated"));
        }

        @Test
        @DisplayName("Non-owner USER cannot UPDATE another user's document - returns 403")
        void nonOwnerCannotUpdate() throws Exception {
            long id = createDocument("alice", "USER", ALICE_DOC_JSON);

            mockMvc.perform(put("/api/documents/" + id)
                            .with(user("bob").roles("USER"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"title\":\"Hijacked\",\"content\":\"bad\"}"))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("ADMIN can UPDATE any document - returns 200")
        void adminCanUpdateAnyDocument() throws Exception {
            long id = createDocument("alice", "USER", ALICE_DOC_JSON);

            mockMvc.perform(put("/api/documents/" + id)
                            .with(user("admin").roles("ADMIN"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"title\":\"Admin Updated\",\"content\":\"fixed\"}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.title").value("Admin Updated"));
        }
    }

    // ---------------------------------------------------------------------------
    // Delete document — @PreAuthorize("hasRole('ADMIN')")
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("Delete document (@PreAuthorize ADMIN only)")
    class DeleteDocument {

        @Test
        @DisplayName("USER cannot DELETE a document - returns 403")
        void userCannotDelete() throws Exception {
            long id = createDocument("alice", "USER", ALICE_DOC_JSON);

            mockMvc.perform(delete("/api/documents/" + id)
                            .with(user("alice").roles("USER")))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("ADMIN can DELETE a document - returns 204")
        void adminCanDelete() throws Exception {
            long id = createDocument("alice", "USER", ALICE_DOC_JSON);

            mockMvc.perform(delete("/api/documents/" + id)
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isNoContent());
        }
    }
}
