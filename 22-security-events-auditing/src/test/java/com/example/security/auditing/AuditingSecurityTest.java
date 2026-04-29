package com.example.security.auditing;

import com.example.security.auditing.repository.AuditEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AuditingSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @BeforeEach
    void clearAuditLog() {
        auditEventRepository.deleteAll();
    }

    @Nested
    @DisplayName("Profile endpoint access control")
    class ProfileAccess {

        @Test
        @DisplayName("unauthenticated request to /api/profile returns 401")
        void unauthenticatedProfileReturns401() throws Exception {
            mockMvc.perform(get("/api/profile"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("authenticated USER can access /api/profile")
        void authenticatedUserCanAccessProfile() throws Exception {
            mockMvc.perform(get("/api/profile")
                            .with(user("user").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.username").value("user"));
        }

        @Test
        @DisplayName("authenticated ADMIN can access /api/profile")
        void authenticatedAdminCanAccessProfile() throws Exception {
            mockMvc.perform(get("/api/profile")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.username").value("admin"));
        }
    }

    @Nested
    @DisplayName("Audit log endpoint access control")
    class AuditLogAccess {

        @Test
        @DisplayName("unauthenticated request to /api/audit-log returns 401")
        void unauthenticatedAuditLogReturns401() throws Exception {
            mockMvc.perform(get("/api/audit-log"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("USER role cannot access /api/audit-log — returns 403")
        void userRoleCannotAccessAuditLog() throws Exception {
            mockMvc.perform(get("/api/audit-log")
                            .with(user("user").roles("USER")))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("ADMIN role can access /api/audit-log and receives JSON array")
        void adminCanAccessAuditLog() throws Exception {
            mockMvc.perform(get("/api/audit-log")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
        }
    }

    @Nested
    @DisplayName("Authorization event publishing")
    class AuthorizationEvents {

        @Test
        @DisplayName("accessing /api/profile publishes an authorization audit event")
        void profileAccessPublishesAuthorizationEvent() throws Exception {
            mockMvc.perform(get("/api/profile")
                            .with(user("user").roles("USER")))
                    .andExpect(status().isOk());

            var events = auditEventRepository.findByUsernameOrderByTimestampDesc("user");
            assertThat(events).isNotEmpty();
            assertThat(events.get(0).getEventType()).isEqualTo("AUTHZ_GRANTED");
            assertThat(events.get(0).getDetails()).contains("/api/profile");
        }
    }
}
