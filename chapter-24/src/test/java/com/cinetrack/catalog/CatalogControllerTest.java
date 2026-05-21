package com.cinetrack.catalog;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for CatalogController authorization rules and actuator exposure.
 *
 * Uses @SpringBootTest so actuator endpoints are fully configured alongside
 * the application security rules. @WithMockUser injects a synthetic principal : 
 * the fastest option when only role-based access control is under test.
 */
@SpringBootTest
@AutoConfigureMockMvc
class CatalogControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void getMovies_authenticated_returns200() throws Exception {
        mockMvc.perform(get("/api/catalog/movies")
                        .with(user("alice").roles("USER")))
                .andExpect(status().isOk());
    }

    @Test
    void getMovies_unauthenticated_returns401() throws Exception {
        mockMvc.perform(get("/api/catalog/movies"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void actuatorHealth_public_returns200() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk());
    }

    @Test
    void actuatorMetrics_requiresAdmin() throws Exception {
        mockMvc.perform(get("/actuator/metrics"))
                .andExpect(status().isUnauthorized());
    }
}
