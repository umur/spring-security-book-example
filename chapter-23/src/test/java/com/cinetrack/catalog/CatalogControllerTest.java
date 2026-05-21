package com.cinetrack.catalog;

import com.cinetrack.security.JwkConfig;
import com.cinetrack.security.SecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MockMvc slice tests for CatalogController covering the jwt() post-processor.
 *
 * jwt() injects a synthetic token directly into the security context: no
 * signature verification occurs. Each test controls exactly which claims and
 * authorities are present, making the intent of each authorization rule clear.
 */
@WebMvcTest(CatalogController.class)
@Import({SecurityConfig.class, JwkConfig.class})
class CatalogControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void getMovies_withCatalogReadScope_returns200() throws Exception {
        mockMvc.perform(get("/api/catalog/movies")
                .with(jwt().jwt(b -> b.claim("scope", "catalog:read"))))
                .andExpect(status().isOk());
    }

    @Test
    void getMovies_withoutToken_returns401() throws Exception {
        mockMvc.perform(get("/api/catalog/movies"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void getMovies_withTokenButNoScope_returns403() throws Exception {
        mockMvc.perform(get("/api/catalog/movies")
                .with(jwt()))
                .andExpect(status().isForbidden());
    }

    @Test
    void createMovie_asAdmin_returns201() throws Exception {
        mockMvc.perform(post("/api/catalog/movies")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"id":"99","title":"Dune","genre":"Science Fiction"}
                        """))
                .andExpect(status().isCreated());
    }

    @Test
    void createMovie_asUser_returns403() throws Exception {
        mockMvc.perform(post("/api/catalog/movies")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"id":"99","title":"Dune","genre":"Science Fiction"}
                        """))
                .andExpect(status().isForbidden());
    }

    @Test
    void deleteMovie_asAdmin_returns204() throws Exception {
        mockMvc.perform(delete("/api/catalog/movies/1")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isNoContent());
    }
}
