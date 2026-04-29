package com.example.security.rbac;

import com.example.security.rbac.controller.ProjectController.CreateProjectRequest;
import com.example.security.rbac.controller.ProjectController.ProjectResponse;
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
class RbacIntegrationTest {

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
    @DisplayName("Public endpoint")
    class PublicEndpointIT {

        @Test
        @DisplayName("GET /api/public/info returns 200 without auth")
        void publicInfoAccessible() {
            var response = restTemplate.getForEntity("/api/public/info", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("Role-Based Authorization Example");
        }
    }

    @Nested
    @DisplayName("USER role")
    class UserRoleIT {

        @Test
        @DisplayName("USER can view projects")
        void userCanViewProjects() {
            var response = restTemplate
                    .withBasicAuth("user", "user")
                    .getForEntity("/api/projects", ProjectResponse[].class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
        }

        @Test
        @DisplayName("USER cannot create a project - returns 403")
        void userCannotCreateProject() {
            var response = restTemplate
                    .withBasicAuth("user", "user")
                    .postForEntity("/api/projects", new CreateProjectRequest("Blocked", "no"), String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }
    }

    @Nested
    @DisplayName("MANAGER role")
    class ManagerRoleIT {

        @Test
        @DisplayName("MANAGER can create a project - returns 201")
        void managerCanCreateProject() {
            var response = restTemplate
                    .withBasicAuth("manager", "manager")
                    .postForEntity("/api/projects", new CreateProjectRequest("Manager Project", "by manager"), ProjectResponse.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().name()).isEqualTo("Manager Project");
        }

        @Test
        @DisplayName("MANAGER cannot delete a project - returns 403")
        void managerCannotDeleteProject() {
            // Seed a project via admin first
            var created = restTemplate
                    .withBasicAuth("admin", "admin")
                    .postForEntity("/api/projects", new CreateProjectRequest("ForManagerDelete", "temp"), ProjectResponse.class);
            assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            Long id = created.getBody().id();

            // Manager attempts delete
            restTemplate
                    .withBasicAuth("manager", "manager")
                    .delete("/api/projects/" + id);

            // Verify project still exists
            var check = restTemplate
                    .withBasicAuth("user", "user")
                    .getForEntity("/api/projects", ProjectResponse[].class);
            assertThat(check.getBody()).extracting(ProjectResponse::id).contains(id);
        }
    }

    @Nested
    @DisplayName("ADMIN role")
    class AdminRoleIT {

        @Test
        @DisplayName("ADMIN can create and delete projects end-to-end")
        void adminCanCreateAndDelete() {
            // Create
            var created = restTemplate
                    .withBasicAuth("admin", "admin")
                    .postForEntity("/api/projects", new CreateProjectRequest("Admin Project", "by admin"), ProjectResponse.class);
            assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            Long id = created.getBody().id();

            // Delete
            restTemplate
                    .withBasicAuth("admin", "admin")
                    .delete("/api/projects/" + id);

            // Verify project is gone
            var projects = restTemplate
                    .withBasicAuth("user", "user")
                    .getForEntity("/api/projects", ProjectResponse[].class);
            assertThat(projects.getBody()).extracting(ProjectResponse::id).doesNotContain(id);
        }

        @Test
        @DisplayName("ADMIN inherits USER permission: can view projects")
        void adminCanViewProjects() {
            var response = restTemplate
                    .withBasicAuth("admin", "admin")
                    .getForEntity("/api/projects", ProjectResponse[].class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }
    }

    @Nested
    @DisplayName("Role hierarchy end-to-end")
    class RoleHierarchyIT {

        @Test
        @DisplayName("ADMIN inherits MANAGER role: can POST /api/projects")
        void adminInheritsManagerRole() {
            var response = restTemplate
                    .withBasicAuth("admin", "admin")
                    .postForEntity("/api/projects", new CreateProjectRequest("Hierarchy Test", "hierarchy"), ProjectResponse.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        }

        @Test
        @DisplayName("MANAGER inherits USER role: can GET /api/projects")
        void managerInheritsUserRole() {
            var response = restTemplate
                    .withBasicAuth("manager", "manager")
                    .getForEntity("/api/projects", ProjectResponse[].class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        @Test
        @DisplayName("Unauthenticated request returns 401")
        void unauthenticatedReturns401() {
            var response = restTemplate.getForEntity("/api/projects", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }
}
