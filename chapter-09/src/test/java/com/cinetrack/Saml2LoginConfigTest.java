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

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that the SAML2 security configuration wires up correctly:
 * unauthenticated requests are redirected to the SP-initiated SSO endpoint,
 * and authenticated requests pass through.
 *
 * <p>Uses {@code MockMvcBuilders.webAppContextSetup()} with {@code springSecurity()}
 * applied: the correct approach in Spring Boot 4 where {@code @WebMvcTest} and
 * {@code @AutoConfigureMockMvc} slices are no longer available.
 *
 * <p>{@code @WithMockUser} stands in for a real SAML2 assertion so we can test
 * the authorization layer in isolation without a live IdP.
 */
@SpringBootTest
class Saml2LoginConfigTest {

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
    @DisplayName("GET /api/movies without auth → redirect to /saml2/authenticate/cinetrack-okta")
    void unauthenticated_redirectsToSaml2() throws Exception {
        mockMvc.perform(get("/api/movies"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/saml2/authenticate?registrationId=cinetrack-okta"));
    }

    @Test
    @DisplayName("GET /api/movies with @WithMockUser → 200")
    @WithMockUser
    void authenticated_canAccessMovies() throws Exception {
        mockMvc.perform(get("/api/movies"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("GET /saml2/service-provider-metadata/cinetrack-okta → 200")
    void metadataEndpoint_isPublic() throws Exception {
        mockMvc.perform(get("/saml2/service-provider-metadata/cinetrack-okta"))
                .andExpect(status().isOk());
    }
}
