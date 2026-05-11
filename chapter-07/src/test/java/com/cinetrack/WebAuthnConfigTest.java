package com.cinetrack;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the WebAuthn security configuration.
 *
 * <p>Spins up the full servlet stack so the actual {@code SecurityFilterChain}
 * processes every request, exactly as it would in production.
 *
 * <p>MockMvc is constructed via {@code MockMvcBuilders.webAppContextSetup()} with
 * {@code springSecurity()} applied — the correct approach in Spring Boot 4
 * (the {@code @AutoConfigureMockMvc} slice was removed).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class WebAuthnConfigTest {

    @LocalServerPort
    int port;

    @Autowired
    WebApplicationContext context;

    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @Test
    @DisplayName("GET /webauthn/register/options → 302 (redirects to login — not authenticated)")
    void registrationOptions_requiresAuthentication() throws Exception {
        mockMvc.perform(get("/webauthn/register/options"))
                .andExpect(status().isFound());
    }

    @Test
    @DisplayName("GET /webauthn/authenticate/options → 200 (public assertion options endpoint)")
    void authenticationOptions_isPublic() throws Exception {
        mockMvc.perform(get("/webauthn/authenticate/options"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("GET /api/movies without auth → 302 redirect to login")
    void moviesEndpoint_withoutAuth_redirectsToLogin() throws Exception {
        mockMvc.perform(get("/api/movies"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login"));
    }
}
