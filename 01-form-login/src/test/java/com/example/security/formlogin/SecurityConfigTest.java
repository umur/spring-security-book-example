package com.example.security.formlogin;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Nested
    @DisplayName("Unauthenticated access")
    class UnauthenticatedAccess {

        @Test
        @DisplayName("redirects to login page when accessing protected resource")
        void protectedResourceRedirectsToLogin() throws Exception {
            mockMvc.perform(get("/dashboard"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login"));
        }

        @Test
        @DisplayName("login page is publicly accessible")
        void loginPageIsPublic() throws Exception {
            mockMvc.perform(get("/login"))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("CSS resources are publicly accessible")
        void cssIsPublic() throws Exception {
            mockMvc.perform(get("/css/style.css"))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("Authenticated access")
    class AuthenticatedAccess {

        @Test
        @DisplayName("authenticated user can access dashboard")
        void dashboardAccessible() throws Exception {
            mockMvc.perform(get("/dashboard").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(view().name("dashboard"));
        }

        @Test
        @DisplayName("authenticated user redirects from home to dashboard")
        void homeRedirectsToDashboard() throws Exception {
            mockMvc.perform(get("/").with(user("alice").roles("USER")))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/dashboard"));
        }
    }

    @Nested
    @DisplayName("Logout")
    class Logout {

        @Test
        @DisplayName("logout redirects to login page with logout param")
        void logoutRedirects() throws Exception {
            mockMvc.perform(post("/logout").with(user("alice")).with(csrf()))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login?logout"));
        }
    }
}
