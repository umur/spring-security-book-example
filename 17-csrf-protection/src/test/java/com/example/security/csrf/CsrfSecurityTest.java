package com.example.security.csrf;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for CSRF protection behaviour.
 *
 * Key Spring Boot 4 / Spring Security 7 conventions used here:
 * - @AutoConfigureMockMvc from org.springframework.boot.webmvc.test.autoconfigure
 * - .with(user(...)) post-processor instead of @WithMockUser
 * - .with(csrf()) to supply a valid CSRF token in tests that need one
 */
@SpringBootTest
@AutoConfigureMockMvc
class CsrfSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    // -------------------------------------------------------------------------
    // Form endpoint — session-based CSRF (default HttpSessionCsrfTokenRepository)
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Form endpoint: POST /transfer (session-based CSRF)")
    class FormTransfer {

        @Test
        @DisplayName("POST /transfer WITHOUT CSRF token returns 403 Forbidden")
        void postTransferWithoutCsrfToken_returns403() throws Exception {
            mockMvc.perform(post("/transfer")
                            .with(user("user").roles("USER"))
                            .param("toAccount", "ACC-999")
                            .param("amount", "50.00"))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("POST /transfer WITH valid CSRF token returns 200")
        void postTransferWithCsrfToken_returns200() throws Exception {
            mockMvc.perform(post("/transfer")
                            .with(user("user").roles("USER"))
                            .with(csrf())
                            .param("toAccount", "ACC-999")
                            .param("amount", "50.00"))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("GET /transfer (form page) returns 200 and contains CSRF token in HTML")
        void getTransferForm_returns200_withCsrfToken() throws Exception {
            mockMvc.perform(get("/transfer")
                            .with(user("user").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(content().string(containsString("_csrf")));
        }

        @Test
        @DisplayName("GET /transfer does not require a CSRF token")
        void getTransferForm_doesNotRequireCsrfToken() throws Exception {
            // GET without .with(csrf()) — must succeed, CSRF is only checked on mutating methods
            mockMvc.perform(get("/transfer")
                            .with(user("user").roles("USER")))
                    .andExpect(status().isOk());
        }
    }

    // -------------------------------------------------------------------------
    // API endpoint — cookie-based CSRF (CookieCsrfTokenRepository)
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("API endpoint: POST /api/transfer (cookie-based CSRF)")
    class ApiTransfer {

        @Test
        @DisplayName("POST /api/transfer WITHOUT CSRF token returns 403 Forbidden")
        void postApiTransferWithoutCsrfToken_returns403() throws Exception {
            mockMvc.perform(post("/api/transfer")
                            .with(user("user").roles("USER"))
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .param("toAccount", "ACC-123")
                            .param("amount", "100.00"))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("POST /api/transfer WITH valid CSRF cookie+header returns 200")
        void postApiTransferWithCsrfToken_returns200() throws Exception {
            mockMvc.perform(post("/api/transfer")
                            .with(user("user").roles("USER"))
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .param("toAccount", "ACC-123")
                            .param("amount", "100.00"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value("success"));
        }

        @Test
        @DisplayName("GET /csrf-token returns 200 and CSRF token details")
        void getCsrfToken_returns200() throws Exception {
            mockMvc.perform(get("/csrf-token")
                            .with(user("user").roles("USER")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("GET requests to /api/** do not require CSRF token")
        void getRequestsDoNotRequireCsrfToken() throws Exception {
            // No .with(csrf()) — GET is safe and should not be CSRF-protected
            mockMvc.perform(get("/csrf-token")
                            .with(user("user").roles("USER")))
                    .andExpect(status().isOk());
        }
    }

    // -------------------------------------------------------------------------
    // Unauthenticated access
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Unauthenticated access")
    class UnauthenticatedAccess {

        @Test
        @DisplayName("GET /transfer without authentication redirects to login")
        void getTransferUnauthenticated_redirectsToLogin() throws Exception {
            mockMvc.perform(get("/transfer"))
                    .andExpect(status().is3xxRedirection());
        }

        @Test
        @DisplayName("POST /api/transfer without authentication returns 401")
        void postApiTransferUnauthenticated_returns401() throws Exception {
            mockMvc.perform(post("/api/transfer")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .param("toAccount", "ACC-123")
                            .param("amount", "100.00"))
                    .andExpect(status().isUnauthorized());
        }
    }

    // -------------------------------------------------------------------------
    // Login page — public access
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Login page")
    class LoginPage {

        @Test
        @DisplayName("GET /login is publicly accessible")
        void loginPageIsPublic() throws Exception {
            mockMvc.perform(get("/login"))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("POST /login with invalid CSRF token returns 403")
        void postLoginWithInvalidCsrf_returns403() throws Exception {
            mockMvc.perform(post("/login")
                            .param("username", "user")
                            .param("password", "user")
                            .with(csrf().useInvalidToken()))
                    .andExpect(status().isForbidden());
        }
    }
}
