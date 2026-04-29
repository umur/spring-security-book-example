package com.example.security.custompermission;

import com.example.security.custompermission.controller.ProjectController.AddMemberRequest;
import com.example.security.custompermission.controller.ProjectController.CreateProjectRequest;
import com.example.security.custompermission.controller.ProjectController.ProjectResponse;
import com.example.security.custompermission.controller.ProjectController.UpdateProjectRequest;
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
class CustomPermissionEvaluatorTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private long createProject(String username, String name) throws Exception {
        String body = objectMapper.writeValueAsString(new CreateProjectRequest(name, "description"));
        MvcResult result = mockMvc.perform(post("/api/projects")
                        .with(user(username).roles("USER"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andReturn();
        return objectMapper.readValue(result.getResponse().getContentAsString(),
                ProjectResponse.class).id();
    }

    private void addMember(String ownerUsername, long projectId, String memberUsername, String role) throws Exception {
        String body = objectMapper.writeValueAsString(new AddMemberRequest(memberUsername, role));
        mockMvc.perform(post("/api/projects/" + projectId + "/members")
                        .with(user(ownerUsername).roles("USER"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated());
    }

    // -----------------------------------------------------------------------
    // Unauthenticated
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Unauthenticated access")
    class Unauthenticated {

        @Test
        @DisplayName("GET /api/projects without credentials returns 401")
        void unauthenticated() throws Exception {
            mockMvc.perform(get("/api/projects"))
                    .andExpect(status().isUnauthorized());
        }
    }

    // -----------------------------------------------------------------------
    // Owner can view, edit, and delete
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Owner permissions")
    class OwnerPermissions {

        @Test
        @DisplayName("Owner can VIEW their project — returns 200")
        void ownerCanView() throws Exception {
            long id = createProject("alice", "Alice Owner View");

            mockMvc.perform(get("/api/projects/" + id)
                            .with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.name").value("Alice Owner View"));
        }

        @Test
        @DisplayName("Owner can EDIT their project — returns 200")
        void ownerCanEdit() throws Exception {
            long id = createProject("alice", "Alice Owner Edit");

            String body = objectMapper.writeValueAsString(new UpdateProjectRequest("Updated Name", "new desc"));
            mockMvc.perform(put("/api/projects/" + id)
                            .with(user("alice").roles("USER"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(body))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.name").value("Updated Name"));
        }

        @Test
        @DisplayName("Owner can DELETE their project — returns 204")
        void ownerCanDelete() throws Exception {
            long id = createProject("alice", "Alice Owner Delete");

            mockMvc.perform(delete("/api/projects/" + id)
                            .with(user("alice").roles("USER")))
                    .andExpect(status().isNoContent());
        }
    }

    // -----------------------------------------------------------------------
    // Editor can view and edit, but not delete
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Editor permissions")
    class EditorPermissions {

        @Test
        @DisplayName("Editor can VIEW the project — returns 200")
        void editorCanView() throws Exception {
            long id = createProject("alice", "Editor View");
            addMember("alice", id, "bob", "EDITOR");

            mockMvc.perform(get("/api/projects/" + id)
                            .with(user("bob").roles("USER")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("Editor can EDIT the project — returns 200")
        void editorCanEdit() throws Exception {
            long id = createProject("alice", "Editor Edit");
            addMember("alice", id, "bob", "EDITOR");

            String body = objectMapper.writeValueAsString(new UpdateProjectRequest("Bob Edited", "desc"));
            mockMvc.perform(put("/api/projects/" + id)
                            .with(user("bob").roles("USER"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(body))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.name").value("Bob Edited"));
        }

        @Test
        @DisplayName("Editor cannot DELETE the project — returns 403")
        void editorCannotDelete() throws Exception {
            long id = createProject("alice", "Editor No Delete");
            addMember("alice", id, "bob", "EDITOR");

            mockMvc.perform(delete("/api/projects/" + id)
                            .with(user("bob").roles("USER")))
                    .andExpect(status().isForbidden());
        }
    }

    // -----------------------------------------------------------------------
    // Viewer can only view
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Viewer permissions")
    class ViewerPermissions {

        @Test
        @DisplayName("Viewer can VIEW the project — returns 200")
        void viewerCanView() throws Exception {
            long id = createProject("alice", "Viewer View");
            addMember("alice", id, "charlie", "VIEWER");

            mockMvc.perform(get("/api/projects/" + id)
                            .with(user("charlie").roles("USER")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("Viewer cannot EDIT the project — returns 403")
        void viewerCannotEdit() throws Exception {
            long id = createProject("alice", "Viewer No Edit");
            addMember("alice", id, "charlie", "VIEWER");

            String body = objectMapper.writeValueAsString(new UpdateProjectRequest("Hijacked", "bad"));
            mockMvc.perform(put("/api/projects/" + id)
                            .with(user("charlie").roles("USER"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(body))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("Viewer cannot DELETE the project — returns 403")
        void viewerCannotDelete() throws Exception {
            long id = createProject("alice", "Viewer No Delete");
            addMember("alice", id, "charlie", "VIEWER");

            mockMvc.perform(delete("/api/projects/" + id)
                            .with(user("charlie").roles("USER")))
                    .andExpect(status().isForbidden());
        }
    }

    // -----------------------------------------------------------------------
    // Non-member gets 403
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Non-member access")
    class NonMemberAccess {

        @Test
        @DisplayName("Non-member cannot VIEW the project — returns 403")
        void nonMemberCannotView() throws Exception {
            long id = createProject("alice", "Non-member View");

            mockMvc.perform(get("/api/projects/" + id)
                            .with(user("diana").roles("USER")))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("Non-member cannot EDIT the project — returns 403")
        void nonMemberCannotEdit() throws Exception {
            long id = createProject("alice", "Non-member Edit");

            String body = objectMapper.writeValueAsString(new UpdateProjectRequest("Hijacked", "bad"));
            mockMvc.perform(put("/api/projects/" + id)
                            .with(user("diana").roles("USER"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(body))
                    .andExpect(status().isForbidden());
        }
    }

    // -----------------------------------------------------------------------
    // Adding a member grants them permissions
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Adding member grants permissions")
    class AddMemberGrantsPermissions {

        @Test
        @DisplayName("After adding as VIEWER, user can view project")
        void addingViewerGrantsView() throws Exception {
            long id = createProject("alice", "Grant Viewer");

            // Before adding — denied
            mockMvc.perform(get("/api/projects/" + id)
                            .with(user("bob").roles("USER")))
                    .andExpect(status().isForbidden());

            addMember("alice", id, "bob", "VIEWER");

            // After adding — allowed
            mockMvc.perform(get("/api/projects/" + id)
                            .with(user("bob").roles("USER")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("After adding as EDITOR, user can edit project")
        void addingEditorGrantsEdit() throws Exception {
            long id = createProject("alice", "Grant Editor");
            addMember("alice", id, "bob", "EDITOR");

            String body = objectMapper.writeValueAsString(new UpdateProjectRequest("Editor Updated", "desc"));
            mockMvc.perform(put("/api/projects/" + id)
                            .with(user("bob").roles("USER"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(body))
                    .andExpect(status().isOk());
        }
    }
}
