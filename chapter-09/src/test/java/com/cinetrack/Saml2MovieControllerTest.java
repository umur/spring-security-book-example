package com.cinetrack;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.hamcrest.Matchers.hasItem;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Slice tests for the movie catalog under the SAML2 security filter chain.
 *
 * <p>Covers two scenarios:
 * <ol>
 *   <li>An authenticated SAML2 principal (simulated with {@code @WithMockUser})
 *       can read the movie catalog and receives the full JSON array.</li>
 *   <li>An unauthenticated request is redirected to the SAML2 SP-initiated SSO
 *       endpoint — not to a form-login page.</li>
 * </ol>
 */
@SpringBootTest
class Saml2MovieControllerTest {

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
    @DisplayName("Authenticated SAML2 principal can access /api/movies")
    @WithMockUser(username = "alice@cinetrack.io")
    void authenticatedSaml2User_canListMovies() throws Exception {
        mockMvc.perform(get("/api/movies"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].title", hasItem("Inception")))
                .andExpect(jsonPath("$[*].title", hasItem("Interstellar")))
                .andExpect(jsonPath("$[*].title", hasItem("The Dark Knight")));
    }

    @Test
    @DisplayName("Unauthenticated request redirects to SAML2 IdP")
    void unauthenticated_redirectsToIdp() throws Exception {
        mockMvc.perform(get("/api/movies"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/saml2/authenticate?registrationId=cinetrack-okta"));
    }
}
