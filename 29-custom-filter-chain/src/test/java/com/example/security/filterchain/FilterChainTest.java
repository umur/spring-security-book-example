package com.example.security.filterchain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class FilterChainTest {

    @Autowired
    private MockMvc mockMvc;

    @Nested
    @DisplayName("Public chain — /api/public/**")
    class PublicChain {

        @Test
        @DisplayName("/api/public/info is accessible without authentication")
        void publicInfoNoAuthRequired() throws Exception {
            mockMvc.perform(get("/api/public/info"))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.status").value("ok"));
        }

        @Test
        @DisplayName("/api/public/info response contains X-Rate-Limit-Remaining header")
        void publicInfoHasRateLimitHeader() throws Exception {
            mockMvc.perform(get("/api/public/info"))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("X-Rate-Limit-Remaining"));
        }
    }

    @Nested
    @DisplayName("User chain — /api/**")
    class UserChain {

        @Test
        @DisplayName("/api/data returns 401 without credentials")
        void dataRequiresAuth() throws Exception {
            mockMvc.perform(get("/api/data"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("/api/data is accessible with USER role")
        void dataAccessibleWithUserRole() throws Exception {
            mockMvc.perform(get("/api/data").with(user("user").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.resource").value("user-data"));
        }

        @Test
        @DisplayName("/api/data returns X-Rate-Limit-Remaining header for authenticated user")
        void dataHasRateLimitHeader() throws Exception {
            mockMvc.perform(get("/api/data").with(user("user").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("X-Rate-Limit-Remaining"));
        }
    }

    @Nested
    @DisplayName("Admin chain — /api/admin/**")
    class AdminChain {

        @Test
        @DisplayName("/api/admin/settings returns 401 without credentials")
        void adminSettingsRequiresAuth() throws Exception {
            mockMvc.perform(get("/api/admin/settings"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("/api/admin/settings returns 403 for USER role")
        void adminSettingsForbiddenForUser() throws Exception {
            mockMvc.perform(get("/api/admin/settings").with(user("user").roles("USER")))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("/api/admin/settings is accessible with ADMIN role")
        void adminSettingsAccessibleWithAdminRole() throws Exception {
            mockMvc.perform(get("/api/admin/settings").with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.resource").value("admin-settings"));
        }

        @Test
        @DisplayName("/api/admin/audit is accessible with ADMIN role")
        void adminAuditAccessibleWithAdminRole() throws Exception {
            mockMvc.perform(get("/api/admin/audit").with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.resource").value("audit-log"));
        }

        @Test
        @DisplayName("/api/admin/settings response contains X-Rate-Limit-Remaining header")
        void adminSettingsHasRateLimitHeader() throws Exception {
            mockMvc.perform(get("/api/admin/settings").with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("X-Rate-Limit-Remaining"));
        }
    }

    @Nested
    @DisplayName("Chain ordering")
    class ChainOrdering {

        @Test
        @DisplayName("ADMIN user can access /api/admin/** (chain 1 matches before chain 3)")
        void adminChainMatchesBeforeUserChain() throws Exception {
            mockMvc.perform(get("/api/admin/settings").with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("USER with role USER cannot access /api/admin/** (chain 1 enforces ADMIN)")
        void userRoleBlockedByAdminChain() throws Exception {
            mockMvc.perform(get("/api/admin/settings").with(user("user").roles("USER")))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("/api/public/** is matched by chain 2 before chain 3 — no auth needed")
        void publicChainMatchesBeforeUserChain() throws Exception {
            mockMvc.perform(get("/api/public/info"))
                    .andExpect(status().isOk());
        }
    }
}
