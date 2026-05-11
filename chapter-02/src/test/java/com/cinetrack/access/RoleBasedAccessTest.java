package com.cinetrack.access;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that role-based access rules are correctly enforced.
 *
 * All three in-memory users (alice/VIEWER, bob/VIEWER, admin/ADMIN) are defined
 * in SecurityConfig — no mocking needed.
 */
@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
class RoleBasedAccessTest {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @Test
    void viewer_canAccessMovies() throws Exception {
        mockMvc.perform(get("/api/movies")
                        .with(httpBasic("alice", "password")))
                .andExpect(status().isOk());
    }

    @Test
    void viewer_cannotAccessAdminEndpoint_returns403() throws Exception {
        mockMvc.perform(get("/api/admin/users")
                        .with(httpBasic("alice", "password")))
                .andExpect(status().isForbidden());
    }

    @Test
    void admin_canAccessAdminEndpoint() throws Exception {
        mockMvc.perform(get("/api/admin/users")
                        .with(httpBasic("admin", "admin")))
                .andExpect(status().isOk());
    }

    @Test
    void anonymous_cannotAccessMovies_returns401() throws Exception {
        mockMvc.perform(get("/api/movies"))
                .andExpect(status().isUnauthorized());
    }
}
