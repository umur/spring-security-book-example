package com.example.security.rememberme;

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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@SpringBootTest
@AutoConfigureMockMvc
class RememberMeSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Nested
    @DisplayName("Unauthenticated access")
    class UnauthenticatedAccess {

        @Test
        @DisplayName("unauthenticated access to dashboard redirects to login")
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
    }

    @Nested
    @DisplayName("Form login")
    class FormLogin {

        @Test
        @DisplayName("valid credentials grant access to dashboard")
        void validCredentialsGrantAccess() throws Exception {
            mockMvc.perform(get("/dashboard").with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(view().name("dashboard"));
        }

        @Test
        @DisplayName("POST login with valid credentials redirects to dashboard")
        void postLoginWithValidCredentials() throws Exception {
            mockMvc.perform(post("/login").with(csrf())
                            .param("username", "admin")
                            .param("password", "admin"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/dashboard"));
        }
    }

    @Nested
    @DisplayName("Logout")
    class Logout {

        @Test
        @DisplayName("logout clears session and redirects to login")
        void logoutClearsSession() throws Exception {
            mockMvc.perform(post("/logout").with(user("admin")).with(csrf()))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login?logout"));
        }
    }

    @Nested
    @DisplayName("Remember-me cookie")
    class RememberMeCookie {

        @Test
        @DisplayName("login with remember-me parameter sets remember-me cookie")
        void loginWithRememberMeSetsCooke() throws Exception {
            mockMvc.perform(post("/login").with(csrf())
                            .param("username", "user")
                            .param("password", "user")
                            .param("remember-me", "on"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(cookie().exists("remember-me"));
        }

        @Test
        @DisplayName("login without remember-me parameter does not set remember-me cookie")
        void loginWithoutRememberMeDoesNotSetCookie() throws Exception {
            mockMvc.perform(post("/login").with(csrf())
                            .param("username", "user")
                            .param("password", "user"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(cookie().doesNotExist("remember-me"));
        }
    }
}
