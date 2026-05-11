package com.cinetrack;

import com.cinetrack.movie.MovieController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that the resource server correctly enforces JWT presence and scope.
 *
 * Uses SecurityMockMvcRequestPostProcessors.jwt() to inject pre-built
 * JwtAuthenticationToken instances directly into the security context — no
 * real token signing happens here, which keeps the tests fast and independent
 * of the JwkConfig key-generation logic.
 */
@WebMvcTest(MovieController.class)
@Import({com.cinetrack.security.SecurityConfig.class})
class JwtValidationTest {

    @MockitoBean
    JwtDecoder jwtDecoder;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void noToken_returns401() throws Exception {
        mockMvc.perform(get("/api/movies"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void validJwtWithCatalogReadScope_returns200() throws Exception {
        mockMvc.perform(get("/api/movies")
                        .with(jwt().jwt(builder -> builder
                                .claim("scope", "catalog:read")
                        )))
                .andExpect(status().isOk());
    }

    @Test
    void validJwtWithoutRequiredScope_returns403() throws Exception {
        // Token is valid but has a different scope — authorization fails, not authentication.
        mockMvc.perform(get("/api/movies")
                        .with(jwt().jwt(builder -> builder
                                .claim("scope", "catalog:write")
                        )))
                .andExpect(status().isForbidden());
    }

    @Test
    void validJwtWithNoScopeClaim_returns403() throws Exception {
        // A token with no scope claim at all yields no authorities.
        mockMvc.perform(get("/api/movies")
                        .with(jwt()))
                .andExpect(status().isForbidden());
    }
}
