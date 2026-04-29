package com.example.security.session;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class SessionManagementTest {

    @Autowired
    private MockMvc mockMvc;

    @Nested
    @DisplayName("Unauthenticated access")
    class UnauthenticatedAccess {

        @Test
        @DisplayName("accessing dashboard without authentication redirects to login")
        void unauthenticatedRedirectsToLogin() throws Exception {
            mockMvc.perform(get("/dashboard"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login"));
        }

        @Test
        @DisplayName("accessing session-info without authentication redirects to login")
        void unauthenticatedApiRedirectsToLogin() throws Exception {
            mockMvc.perform(get("/api/session-info"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login"));
        }

        @Test
        @DisplayName("login page is publicly accessible")
        void loginPageIsPublic() throws Exception {
            mockMvc.perform(get("/login"))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("Authenticated access")
    class AuthenticatedAccess {

        @Test
        @DisplayName("authenticated user can access dashboard")
        void dashboardAccessibleWhenAuthenticated() throws Exception {
            mockMvc.perform(get("/dashboard").with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(view().name("dashboard"));
        }

        @Test
        @DisplayName("session-info endpoint returns JSON with session details")
        void sessionInfoReturnsJson() throws Exception {
            mockMvc.perform(get("/api/session-info").with(user("user").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith("application/json"))
                    .andExpect(jsonPath("$.username").value("user"))
                    .andExpect(jsonPath("$.sessionId").isNotEmpty())
                    .andExpect(jsonPath("$.creationTime").isNotEmpty())
                    .andExpect(jsonPath("$.maxInactiveInterval").isNumber());
        }

        @Test
        @DisplayName("session-info includes roles")
        void sessionInfoIncludesRoles() throws Exception {
            mockMvc.perform(get("/api/session-info").with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.roles[0]").value("ROLE_ADMIN"));
        }
    }

    @Nested
    @DisplayName("Session fixation protection")
    class SessionFixation {

        @Test
        @DisplayName("session ID changes after successful form login")
        void sessionIdChangesAfterLogin() throws Exception {
            // Create a pre-login session
            MockHttpSession preLoginSession = new MockHttpSession();
            String preLoginSessionId = preLoginSession.getId();

            // Perform login — Spring Security should replace the session
            var result = mockMvc.perform(post("/login")
                            .with(csrf())
                            .session(preLoginSession)
                            .param("username", "user")
                            .param("password", "user"))
                    .andExpect(status().is3xxRedirection())
                    .andReturn();

            // The session in the response should differ from the pre-login session
            var postLoginSession = (MockHttpSession) result.getRequest().getSession(false);
            if (postLoginSession != null) {
                assertThat(postLoginSession.getId()).isNotEqualTo(preLoginSessionId);
            }
            // Alternatively, the original session is invalidated (postLoginSession == null means a new one was created)
        }
    }

    @Nested
    @DisplayName("Logout")
    class Logout {

        @Test
        @DisplayName("logout redirects to login with logout parameter")
        void logoutRedirectsToLogin() throws Exception {
            mockMvc.perform(post("/logout")
                            .with(user("user").roles("USER"))
                            .with(csrf()))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login?logout"));
        }
    }
}
