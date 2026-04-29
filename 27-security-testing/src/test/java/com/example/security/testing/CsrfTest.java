package com.example.security.testing;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * CSRF protection testing reference.
 *
 * Key patterns demonstrated:
 *   .with(csrf())                  — provides a valid CSRF token (synch-token pattern)
 *   .with(csrf().useInvalidToken()) — provides an invalid token → expects 403
 *   GET requests                   — never CSRF-protected (safe method)
 *   POST without token             — always rejected when CSRF enabled
 *   Unauthenticated POST with token — rejected with 401 (auth checked first)
 *
 * How .with(csrf()) works:
 *   Spring Security's test support generates a CsrfRequestPostProcessor that
 *   stores a valid CSRF token in the mock session and adds it as a request
 *   parameter (_csrf) or header (X-CSRF-TOKEN). The exact mechanism depends on
 *   the configured CsrfTokenRepository; the test infrastructure handles both.
 */
@SpringBootTest
@AutoConfigureMockMvc
class CsrfTest {

    @Autowired
    MockMvc mockMvc;

    // =========================================================================
    // Safe methods (GET, HEAD, OPTIONS, TRACE) — never CSRF-protected
    // =========================================================================

    @Nested
    @DisplayName("Safe HTTP methods — no CSRF token needed")
    class SafeMethods {

        @Test
        @DisplayName("GET /api/user without CSRF token returns 200")
        void getDoesNotRequireCsrf() throws Exception {
            mockMvc.perform(get("/api/user").with(user("alice").roles("USER")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("GET /api/admin without CSRF token returns 200 for ADMIN")
        void getAdminDoesNotRequireCsrf() throws Exception {
            mockMvc.perform(get("/api/admin").with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk());
        }
    }

    // =========================================================================
    // POST /api/data — CSRF-protected mutating endpoint
    // =========================================================================

    @Nested
    @DisplayName("POST /api/data — CSRF enforcement")
    class PostWithCsrf {

        private static final String VALID_BODY = "{\"content\":\"hello\"}";

        @Test
        @DisplayName("POST without CSRF token — authenticated user gets 403")
        void postWithoutCsrfReturns403() throws Exception {
            mockMvc.perform(post("/api/data")
                            .with(user("alice").roles("USER"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(VALID_BODY))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("POST with valid CSRF token — authenticated user gets 201")
        void postWithValidCsrfReturns201() throws Exception {
            mockMvc.perform(post("/api/data")
                            .with(user("alice").roles("USER"))
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(VALID_BODY))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.owner").value("alice"))
                    .andExpect(jsonPath("$.status").value("created"));
        }

        @Test
        @DisplayName("POST with invalid CSRF token — returns 403")
        void postWithInvalidCsrfReturns403() throws Exception {
            mockMvc.perform(post("/api/data")
                            .with(user("alice").roles("USER"))
                            .with(csrf().useInvalidToken())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(VALID_BODY))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("POST with CSRF token but unauthenticated — returns 401 (auth before CSRF)")
        void postWithCsrfButUnauthenticatedReturns401() throws Exception {
            // Spring Security checks authentication before CSRF when the
            // session is anonymous — so we get 401, not 403.
            mockMvc.perform(post("/api/data")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(VALID_BODY))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("ADMIN can POST with CSRF token — returns 201")
        void adminCanPostWithCsrf() throws Exception {
            mockMvc.perform(post("/api/data")
                            .with(user("admin").roles("ADMIN"))
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"content\":\"admin-data\"}"))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.owner").value("admin"));
        }
    }

    // =========================================================================
    // /api/public — CSRF disabled for this path (ignoringRequestMatchers)
    // =========================================================================

    @Nested
    @DisplayName("/api/public — CSRF disabled via ignoringRequestMatchers")
    class PublicEndpointCsrfExempt {

        @Test
        @DisplayName("GET /api/public — no auth, no CSRF needed — returns 200")
        void publicGetNoAuth() throws Exception {
            mockMvc.perform(get("/api/public"))
                    .andExpect(status().isOk());
        }
    }
}
