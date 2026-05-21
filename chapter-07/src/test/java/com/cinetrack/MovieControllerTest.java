package com.cinetrack;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests the MovieController access rules in the WebAuthn chapter.
 * Authenticated users (via form login) reach the catalog endpoint.
 * Unauthenticated requests are redirected to /login.
 */
@SpringBootTest
class MovieControllerTest {

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
    void moviesEndpoint_unauthenticated_redirectsToLogin() throws Exception {
        mockMvc.perform(get("/api/movies"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void moviesEndpoint_authenticatedUser_returns200AndMovies() throws Exception {
        mockMvc.perform(get("/api/movies")
                        .with(user("alice").password("alice123").roles("USER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].title").value("Inception"))
                .andExpect(jsonPath("$[0].id").value(1))
                .andExpect(jsonPath("$[0].year").value(2010))
                .andExpect(jsonPath("$.length()").value(3));
    }

    @Test
    void webauthnAssertionOptions_isPublic_returns200() throws Exception {
        mockMvc.perform(get("/webauthn/authenticate/options"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challenge").exists());
    }
}
