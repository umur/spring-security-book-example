package com.example.security.rbac;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class RbacSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    private static final String CREATE_PROJECT_JSON = """
            {"name":"Test Project","description":"A test"}
            """;

    @Nested
    @DisplayName("Public endpoint")
    class PublicEndpoint {

        @Test
        @DisplayName("GET /api/public/info is accessible without authentication")
        void publicInfoIsAccessible() throws Exception {
            mockMvc.perform(get("/api/public/info"))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("Unauthenticated access")
    class UnauthenticatedAccess {

        @Test
        @DisplayName("unauthenticated request to GET /api/projects returns 401")
        void unauthenticatedGetReturns401() throws Exception {
            mockMvc.perform(get("/api/projects"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("unauthenticated request to POST /api/projects returns 401")
        void unauthenticatedPostReturns401() throws Exception {
            mockMvc.perform(post("/api/projects")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(CREATE_PROJECT_JSON))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("unauthenticated request to DELETE /api/projects/1 returns 401")
        void unauthenticatedDeleteReturns401() throws Exception {
            mockMvc.perform(delete("/api/projects/1"))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("USER role")
    class UserRole {

        @Test
        @DisplayName("USER can GET /api/projects")
        void userCanGetProjects() throws Exception {
            mockMvc.perform(get("/api/projects").with(user("user").roles("USER")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("USER cannot POST /api/projects - returns 403")
        void userCannotCreateProject() throws Exception {
            mockMvc.perform(post("/api/projects")
                            .with(user("user").roles("USER"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(CREATE_PROJECT_JSON))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("USER cannot DELETE /api/projects/1 - returns 403")
        void userCannotDeleteProject() throws Exception {
            mockMvc.perform(delete("/api/projects/1").with(user("user").roles("USER")))
                    .andExpect(status().isForbidden());
        }
    }

    @Nested
    @DisplayName("MANAGER role")
    class ManagerRole {

        @Test
        @DisplayName("MANAGER can GET /api/projects")
        void managerCanGetProjects() throws Exception {
            mockMvc.perform(get("/api/projects").with(user("manager").roles("MANAGER")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("MANAGER can POST /api/projects - returns 201")
        void managerCanCreateProject() throws Exception {
            mockMvc.perform(post("/api/projects")
                            .with(user("manager").roles("MANAGER"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(CREATE_PROJECT_JSON))
                    .andExpect(status().isCreated());
        }

        @Test
        @DisplayName("MANAGER cannot DELETE /api/projects/1 - returns 403")
        void managerCannotDeleteProject() throws Exception {
            mockMvc.perform(delete("/api/projects/1").with(user("manager").roles("MANAGER")))
                    .andExpect(status().isForbidden());
        }
    }

    @Nested
    @DisplayName("ADMIN role")
    class AdminRole {

        @Test
        @DisplayName("ADMIN can GET /api/projects")
        void adminCanGetProjects() throws Exception {
            mockMvc.perform(get("/api/projects").with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("ADMIN can POST /api/projects - returns 201")
        void adminCanCreateProject() throws Exception {
            mockMvc.perform(post("/api/projects")
                            .with(user("admin").roles("ADMIN"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(CREATE_PROJECT_JSON))
                    .andExpect(status().isCreated());
        }

        @Test
        @DisplayName("ADMIN can DELETE /api/projects/{id} - returns 204")
        void adminCanDeleteProject() throws Exception {
            // First create a project to delete
            var result = mockMvc.perform(post("/api/projects")
                            .with(user("admin").roles("ADMIN"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"name\":\"To Delete\",\"description\":\"temp\"}"))
                    .andExpect(status().isCreated())
                    .andReturn();

            // Extract id from response body
            String body = result.getResponse().getContentAsString();
            // body looks like {"id":N,...}
            long id = Long.parseLong(body.replaceAll(".*\"id\":(\\d+).*", "$1"));

            mockMvc.perform(delete("/api/projects/" + id).with(user("admin").roles("ADMIN")))
                    .andExpect(status().isNoContent());
        }
    }

    @Nested
    @DisplayName("Role hierarchy")
    class RoleHierarchy {

        @Test
        @DisplayName("ADMIN inherits MANAGER permission: can POST /api/projects")
        void adminInheritsManagerPermission() throws Exception {
            mockMvc.perform(post("/api/projects")
                            .with(user("admin").roles("ADMIN"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(CREATE_PROJECT_JSON))
                    .andExpect(status().isCreated());
        }

        @Test
        @DisplayName("ADMIN inherits USER permission: can GET /api/projects")
        void adminInheritsUserPermission() throws Exception {
            mockMvc.perform(get("/api/projects").with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("MANAGER inherits USER permission: can GET /api/projects")
        void managerInheritsUserPermission() throws Exception {
            mockMvc.perform(get("/api/projects").with(user("manager").roles("MANAGER")))
                    .andExpect(status().isOk());
        }
    }
}
