package com.cinetrack;

import com.cinetrack.movie.MovieController;
import com.cinetrack.security.JwkConfig;
import com.cinetrack.security.SecurityConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * JWT resource server tests using the {@code jwt()} MockMvc post-processor.
 *
 * {@code jwt()} injects a synthetic {@link org.springframework.security.oauth2.jwt.Jwt}
 * directly into the security context, bypassing signature verification. This
 * lets tests control exactly which claims and authorities are present without
 * needing to mint real signed tokens: that work is left to
 * {@link WireMockJwksTest} which exercises the full decode-and-validate path.
 *
 * Key techniques shown:
 * <ul>
 *   <li>Granting specific scopes via {@code jwt().authorities(...)}.</li>
 *   <li>Adding custom JWT claims via {@code jwt().jwt(builder -> ...)}.</li>
 *   <li>Verifying that missing scope → 403 (authenticated but not authorized).</li>
 * </ul>
 */
@WebMvcTest({MovieController.class, com.cinetrack.catalog.CatalogController.class})
@Import({SecurityConfig.class, JwkConfig.class})
class JwtSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("JWT with SCOPE_catalog:read on /api/catalog endpoint returns 200")
    void jwtWithCatalogReadScope_returns200() throws Exception {
        mockMvc.perform(get("/api/catalog/movies")
                .with(jwt()
                    .authorities(new SimpleGrantedAuthority("SCOPE_catalog:read"))
                ))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("JWT without any scope on /api/catalog endpoint returns 403")
    void jwtWithoutScope_returns403() throws Exception {
        mockMvc.perform(get("/api/catalog/movies")
                .with(jwt()))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("JWT with tier=PREMIUM claim is accessible in controller")
    void jwtWithTierClaim_accessibleInController() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/movies/1")
                .with(jwt()
                    .jwt(token -> token
                        .claim("tier", "PREMIUM")
                        .subject("charlie")
                    )
                    .authorities(new SimpleGrantedAuthority("ROLE_USER"))
                ))
                .andExpect(status().isOk())
                .andReturn();

        // The controller reads jwt.getClaimAsString("tier") without throwing : 
        // a successful 200 confirms the claim was accessible.
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("JWT with wrong scope returns 403 on /api/catalog")
    void jwtWithWrongScope_returns403() throws Exception {
        mockMvc.perform(get("/api/catalog/movies")
                .with(jwt()
                    .authorities(new SimpleGrantedAuthority("SCOPE_profile"))
                ))
                .andExpect(status().isForbidden());
    }
}
