package com.example.security.custompermission;

import com.example.security.custompermission.controller.ProjectController.*;
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
class CustomPermissionEvaluatorIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17-alpine");

    @DynamicPropertySource
    static void configureDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
        registry.add("spring.h2.console.enabled", () -> "false");
    }

    @Autowired TestRestTemplate restTemplate;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private ProjectResponse createProject(String user, String pass, String name) {
        ResponseEntity<ProjectResponse> r = restTemplate
                .withBasicAuth(user, pass)
                .postForEntity("/api/projects",
                        new CreateProjectRequest(name, "description"),
                        ProjectResponse.class);
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        return r.getBody();
    }

    private void addMember(String ownerUser, String ownerPass, long projectId,
                            String memberUser, String role) {
        ResponseEntity<MemberResponse> r = restTemplate
                .withBasicAuth(ownerUser, ownerPass)
                .postForEntity("/api/projects/" + projectId + "/members",
                        new AddMemberRequest(memberUser, role),
                        MemberResponse.class);
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    // -----------------------------------------------------------------------
    // Unauthenticated
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Unauthenticated access")
    class Unauthenticated {

        @Test
        @DisplayName("GET /api/projects without credentials returns 401")
        void unauthenticated() {
            ResponseEntity<String> r = restTemplate.getForEntity("/api/projects", String.class);
            assertThat(r.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    // -----------------------------------------------------------------------
    // Owner can view/edit/delete
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Owner permissions (integration)")
    class OwnerPermissionsIT {

        @Test
        @DisplayName("Owner can view, edit, and delete their project")
        void ownerFullControl() {
            ProjectResponse proj = createProject("alice", "alice", "Alice IT Owner");

            // VIEW
            ResponseEntity<ProjectResponse> view = restTemplate
                    .withBasicAuth("alice", "alice")
                    .getForEntity("/api/projects/" + proj.id(), ProjectResponse.class);
            assertThat(view.getStatusCode()).isEqualTo(HttpStatus.OK);

            // EDIT
            ResponseEntity<ProjectResponse> edit = restTemplate
                    .withBasicAuth("alice", "alice")
                    .exchange("/api/projects/" + proj.id(), HttpMethod.PUT,
                            new HttpEntity<>(new UpdateProjectRequest("IT Updated", "desc")),
                            ProjectResponse.class);
            assertThat(edit.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(edit.getBody().name()).isEqualTo("IT Updated");

            // DELETE
            ResponseEntity<Void> del = restTemplate
                    .withBasicAuth("alice", "alice")
                    .exchange("/api/projects/" + proj.id(), HttpMethod.DELETE,
                            HttpEntity.EMPTY, Void.class);
            assertThat(del.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        }
    }

    // -----------------------------------------------------------------------
    // Editor can view/edit but not delete
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Editor permissions (integration)")
    class EditorPermissionsIT {

        @Test
        @DisplayName("Editor can view and edit but not delete")
        void editorLimitedAccess() {
            ProjectResponse proj = createProject("alice", "alice", "Alice IT Editor");
            addMember("alice", "alice", proj.id(), "bob", "EDITOR");

            // VIEW — OK
            ResponseEntity<ProjectResponse> view = restTemplate
                    .withBasicAuth("bob", "bob")
                    .getForEntity("/api/projects/" + proj.id(), ProjectResponse.class);
            assertThat(view.getStatusCode()).isEqualTo(HttpStatus.OK);

            // EDIT — OK
            ResponseEntity<ProjectResponse> edit = restTemplate
                    .withBasicAuth("bob", "bob")
                    .exchange("/api/projects/" + proj.id(), HttpMethod.PUT,
                            new HttpEntity<>(new UpdateProjectRequest("Bob IT Edited", "desc")),
                            ProjectResponse.class);
            assertThat(edit.getStatusCode()).isEqualTo(HttpStatus.OK);

            // DELETE — 403
            ResponseEntity<String> del = restTemplate
                    .withBasicAuth("bob", "bob")
                    .exchange("/api/projects/" + proj.id(), HttpMethod.DELETE,
                            HttpEntity.EMPTY, String.class);
            assertThat(del.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }
    }

    // -----------------------------------------------------------------------
    // Viewer can only view
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Viewer permissions (integration)")
    class ViewerPermissionsIT {

        @Test
        @DisplayName("Viewer can view but not edit or delete")
        void viewerReadOnly() {
            ProjectResponse proj = createProject("alice", "alice", "Alice IT Viewer");
            addMember("alice", "alice", proj.id(), "charlie", "VIEWER");

            // VIEW — OK
            ResponseEntity<ProjectResponse> view = restTemplate
                    .withBasicAuth("charlie", "charlie")
                    .getForEntity("/api/projects/" + proj.id(), ProjectResponse.class);
            assertThat(view.getStatusCode()).isEqualTo(HttpStatus.OK);

            // EDIT — 403
            ResponseEntity<String> edit = restTemplate
                    .withBasicAuth("charlie", "charlie")
                    .exchange("/api/projects/" + proj.id(), HttpMethod.PUT,
                            new HttpEntity<>(new UpdateProjectRequest("Hijacked", "bad")),
                            String.class);
            assertThat(edit.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

            // DELETE — 403
            ResponseEntity<String> del = restTemplate
                    .withBasicAuth("charlie", "charlie")
                    .exchange("/api/projects/" + proj.id(), HttpMethod.DELETE,
                            HttpEntity.EMPTY, String.class);
            assertThat(del.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }
    }

    // -----------------------------------------------------------------------
    // Non-member gets 403
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Non-member access (integration)")
    class NonMemberIT {

        @Test
        @DisplayName("Non-member cannot view project — returns 403")
        void nonMemberDenied() {
            ProjectResponse proj = createProject("alice", "alice", "Alice IT Non-member");

            ResponseEntity<String> r = restTemplate
                    .withBasicAuth("diana", "diana")
                    .getForEntity("/api/projects/" + proj.id(), String.class);
            assertThat(r.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }
    }

    // -----------------------------------------------------------------------
    // Adding a member grants them permissions
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Adding member grants permissions (integration)")
    class AddMemberIT {

        @Test
        @DisplayName("After adding as VIEWER, user can access the project")
        void addingMemberGrantsAccess() {
            ProjectResponse proj = createProject("alice", "alice", "Alice IT Grant");

            // Before — denied
            ResponseEntity<String> before = restTemplate
                    .withBasicAuth("bob", "bob")
                    .getForEntity("/api/projects/" + proj.id(), String.class);
            assertThat(before.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

            addMember("alice", "alice", proj.id(), "bob", "VIEWER");

            // After — allowed
            ResponseEntity<ProjectResponse> after = restTemplate
                    .withBasicAuth("bob", "bob")
                    .getForEntity("/api/projects/" + proj.id(), ProjectResponse.class);
            assertThat(after.getStatusCode()).isEqualTo(HttpStatus.OK);
        }
    }
}
