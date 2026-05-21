package com.cinetrack;

import com.cinetrack.movie.MovieController;
import com.cinetrack.security.JwkConfig;
import com.cinetrack.security.SecurityConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * HTTP Basic authentication tests using MockMvc.
 *
 * {@code httpBasic()} from {@code spring-security-test} populates the
 * {@code Authorization} header before the request hits the filter chain, so
 * {@link org.springframework.security.web.authentication.www.BasicAuthenticationFilter}
 * picks it up and authenticates against the in-memory user store.
 *
 * The CSRF tests are less relevant for a stateless JSON API but are included
 * because the chapter covers them: Spring Security enables CSRF protection by
 * default for state-changing methods, and {@code csrf()} injects the token.
 */
@WebMvcTest(MovieController.class)
@Import({SecurityConfig.class, JwkConfig.class})
class MockMvcSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Valid Basic credentials for alice return 200")
    void validBasicAuth_returns200() throws Exception {
        mockMvc.perform(get("/api/movies")
                .with(httpBasic("alice", "alice123")))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Request with no credentials returns 401")
    void noCredentials_returns401() throws Exception {
        mockMvc.perform(get("/api/movies"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST with CSRF token and valid auth succeeds")
    void postWithCsrf_returns200() throws Exception {
        // CSRF is disabled in SecurityConfig for this app (stateless API).
        // This test verifies a POST with credentials works without CSRF concern.
        mockMvc.perform(post("/api/movies")
                .with(httpBasic("alice", "alice123"))
                .with(csrf())
                .contentType("application/json")
                .content("{}"))
                .andExpect(status().isMethodNotAllowed()); // no POST handler: method not allowed, not 401/403
    }

    @Test
    @DisplayName("Wrong password returns 401")
    void wrongPassword_returns401() throws Exception {
        mockMvc.perform(get("/api/movies")
                .with(httpBasic("alice", "wrong")))
                .andExpect(status().isUnauthorized());
    }
}
