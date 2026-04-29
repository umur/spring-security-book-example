package com.example.security.ratelimit;

import com.example.security.ratelimit.service.LoginAttemptService;
import org.junit.jupiter.api.BeforeEach;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class RateLimitSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @BeforeEach
    void resetAttempts() {
        loginAttemptService.reset();
    }

    @Nested
    @DisplayName("Protected data endpoint")
    class DataEndpoint {

        @Test
        @DisplayName("unauthenticated request to /api/data returns 401")
        void unauthenticatedDataReturns401() throws Exception {
            mockMvc.perform(get("/api/data"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("authenticated USER can access /api/data")
        void authenticatedUserCanAccessData() throws Exception {
            mockMvc.perform(get("/api/data")
                            .with(user("user").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.message").value("Protected data"));
        }
    }

    @Nested
    @DisplayName("Account status endpoint access control")
    class AccountStatusAccess {

        @Test
        @DisplayName("unauthenticated request to /api/account/status returns 401")
        void unauthenticatedStatusReturns401() throws Exception {
            mockMvc.perform(get("/api/account/status").param("username", "user"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("USER role cannot access /api/account/status — returns 403")
        void userRoleCannotAccessStatus() throws Exception {
            mockMvc.perform(get("/api/account/status")
                            .param("username", "user")
                            .with(user("user").roles("USER")))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("ADMIN can access /api/account/status")
        void adminCanAccessStatus() throws Exception {
            mockMvc.perform(get("/api/account/status")
                            .param("username", "user")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.username").value("user"))
                    .andExpect(jsonPath("$.locked").value(false));
        }
    }

    @Nested
    @DisplayName("Login endpoint")
    class LoginEndpoint {

        @Test
        @DisplayName("/api/auth/login is publicly accessible")
        void loginEndpointIsPublic() throws Exception {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"username":"user","password":"user"}
                                    """))
                    .andExpect(status().isOk());
        }
    }
}
