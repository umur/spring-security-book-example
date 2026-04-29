package com.example.security.ldap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Security layer tests using MockMvc with user post-processor (no actual LDAP bind needed).
 * All tests share a single ApplicationContext to avoid LDAP server port conflicts.
 */
@SpringBootTest
@AutoConfigureMockMvc
class LdapSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("no credentials on /api/profile -> 401")
    void noCredentialsReturns401() throws Exception {
        mockMvc.perform(get("/api/profile"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("no credentials on /api/admin -> 401")
    void noCredentialsOnAdminReturns401() throws Exception {
        mockMvc.perform(get("/api/admin"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("valid user -> 200 on GET /api/profile")
    void validUserReturns200OnProfile() throws Exception {
        mockMvc.perform(get("/api/profile")
                        .with(user("user").roles("USER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("user"));
    }

    @Test
    @DisplayName("valid admin -> 200 on GET /api/profile")
    void validAdminReturns200OnProfile() throws Exception {
        mockMvc.perform(get("/api/profile")
                        .with(user("admin").roles("ADMIN", "USER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("admin"));
    }

    @Test
    @DisplayName("USER role -> 403 on GET /api/admin")
    void userRoleOnAdminReturns403() throws Exception {
        mockMvc.perform(get("/api/admin")
                        .with(user("user").roles("USER")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ADMIN role -> 200 on GET /api/admin")
    void adminRoleOnAdminReturns200() throws Exception {
        mockMvc.perform(get("/api/admin")
                        .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Admin area"));
    }
}
