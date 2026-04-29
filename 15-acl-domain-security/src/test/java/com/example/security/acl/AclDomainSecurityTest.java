package com.example.security.acl;

import com.example.security.acl.controller.DocumentController.GrantPermissionRequest;
import com.example.security.acl.dto.DocumentResponse;
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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AclDomainSecurityTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    // -----------------------------------------------------------------------
    // Helper: create a document as a named user, return its id
    // -----------------------------------------------------------------------
    private long createDoc(String username, String title) throws Exception {
        String body = objectMapper.writeValueAsString(new CreateDocReq(title, "content"));
        MvcResult result = mockMvc.perform(post("/api/documents")
                        .with(user(username).roles("USER"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andReturn();
        return objectMapper.readValue(result.getResponse().getContentAsString(),
                DocumentResponse.class).id();
    }

    private void grant(String grantingUser, long docId, String targetUser, String permission) throws Exception {
        String body = objectMapper.writeValueAsString(new GrantPermissionRequest(targetUser, permission));
        mockMvc.perform(put("/api/documents/" + docId + "/permissions")
                        .with(user(grantingUser).roles("USER"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk());
    }

    private record CreateDocReq(String title, String content) {}

    // -----------------------------------------------------------------------
    // Unauthenticated
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Unauthenticated access")
    class Unauthenticated {

        @Test
        @DisplayName("GET /api/documents without credentials returns 401")
        void unauthenticated() throws Exception {
            mockMvc.perform(get("/api/documents"))
                    .andExpect(status().isUnauthorized());
        }
    }

    // -----------------------------------------------------------------------
    // Owner can read their own document
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Owner permissions")
    class OwnerPermissions {

        @Test
        @DisplayName("Owner can GET their document via ACL READ")
        void ownerCanRead() throws Exception {
            long id = createDoc("alice", "Alice Private Doc");

            mockMvc.perform(get("/api/documents/" + id)
                            .with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.owner").value("alice"));
        }

        @Test
        @DisplayName("Owner document appears in their own list")
        void ownerSeesDocInList() throws Exception {
            long id = createDoc("alice", "Alice List Doc");

            MvcResult result = mockMvc.perform(get("/api/documents")
                            .with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andReturn();

            DocumentResponse[] docs = objectMapper.readValue(
                    result.getResponse().getContentAsString(), DocumentResponse[].class);
            assertThat(docs).anyMatch(d -> d.id().equals(id));
        }

        @Test
        @DisplayName("Owner can grant READ to another user")
        void ownerCanGrantRead() throws Exception {
            long id = createDoc("alice", "Alice Grant Doc");
            grant("alice", id, "bob", "READ");

            mockMvc.perform(get("/api/documents/" + id)
                            .with(user("bob").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.owner").value("alice"));
        }
    }

    // -----------------------------------------------------------------------
    // Non-owner without permission gets 403
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Non-owner without permission")
    class NonOwnerWithoutPermission {

        @Test
        @DisplayName("Non-owner without ACL entry cannot GET document — returns 403")
        void nonOwnerDenied() throws Exception {
            long id = createDoc("alice", "Alice Only Doc");

            mockMvc.perform(get("/api/documents/" + id)
                            .with(user("bob").roles("USER")))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("Non-owner document does NOT appear in their list")
        void nonOwnerDocHiddenInList() throws Exception {
            long id = createDoc("alice", "Hidden From Bob");

            MvcResult result = mockMvc.perform(get("/api/documents")
                            .with(user("bob").roles("USER")))
                    .andExpect(status().isOk())
                    .andReturn();

            DocumentResponse[] docs = objectMapper.readValue(
                    result.getResponse().getContentAsString(), DocumentResponse[].class);
            assertThat(docs).noneMatch(d -> d.id().equals(id));
        }
    }

    // -----------------------------------------------------------------------
    // After granting READ — non-owner can read
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Permission grant workflow")
    class PermissionGrant {

        @Test
        @DisplayName("After READ grant, non-owner can successfully GET the document")
        void afterGrantNonOwnerCanRead() throws Exception {
            long id = createDoc("alice", "Shared With Charlie");
            grant("alice", id, "charlie", "READ");

            mockMvc.perform(get("/api/documents/" + id)
                            .with(user("charlie").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.title").value("Shared With Charlie"));
        }

        @Test
        @DisplayName("Non-owner without ADMINISTRATION cannot grant permissions — returns 403")
        void nonOwnerCannotGrant() throws Exception {
            long id = createDoc("alice", "Alice Admin Only");

            String body = objectMapper.writeValueAsString(
                    new GrantPermissionRequest("charlie", "READ"));
            mockMvc.perform(put("/api/documents/" + id + "/permissions")
                            .with(user("bob").roles("USER"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(body))
                    .andExpect(status().isForbidden());
        }
    }

    // -----------------------------------------------------------------------
    // ADMIN can manage all documents
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("ADMIN privileges")
    class AdminPrivileges {

        @Test
        @DisplayName("ADMIN can GET any document regardless of ACL")
        void adminCanReadAny() throws Exception {
            long id = createDoc("alice", "Admin Reads This");

            mockMvc.perform(get("/api/documents/" + id)
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.owner").value("alice"));
        }

        @Test
        @DisplayName("ADMIN can grant permission on any document")
        void adminCanGrant() throws Exception {
            long id = createDoc("alice", "Admin Grants This");
            String body = objectMapper.writeValueAsString(
                    new GrantPermissionRequest("bob", "READ"));
            mockMvc.perform(put("/api/documents/" + id + "/permissions")
                            .with(user("admin").roles("ADMIN"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(body))
                    .andExpect(status().isOk());

            mockMvc.perform(get("/api/documents/" + id)
                            .with(user("bob").roles("USER")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("ADMIN sees all documents in list")
        void adminSeesAll() throws Exception {
            createDoc("alice", "Admin List A");
            createDoc("bob", "Admin List B");

            MvcResult result = mockMvc.perform(get("/api/documents")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andReturn();

            DocumentResponse[] docs = objectMapper.readValue(
                    result.getResponse().getContentAsString(), DocumentResponse[].class);
            long distinctOwners = java.util.Arrays.stream(docs)
                    .map(DocumentResponse::owner)
                    .distinct()
                    .count();
            assertThat(distinctOwners).isGreaterThan(1);
        }
    }
}
