package com.cinetrack.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests the embedded authorization server's well-known and JWKS endpoints.
 *
 * These endpoints are served by the AuthorizationServerConfig chain (Order 1)
 * and must be reachable without authentication. This exercises the
 * userInfoMapper, JWK source, and server settings beans.
 */
@SpringBootTest
@ActiveProfiles("test")
class AuthorizationServerConfigTest {

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
    void oidcDiscoveryEndpoint_isAccessible_returns200() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("http://localhost:8080"));
    }

    @Test
    void jwksEndpoint_isAccessible_returnsKeys() throws Exception {
        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray());
    }

    @Test
    void tokenEndpoint_withoutCredentials_returns400OrUnauthorized() throws Exception {
        mockMvc.perform(get("/oauth2/token"))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    // Either 400 (bad request - missing grant type) or 401/302 (auth required)
                    assert status == 400 || status == 401 || status == 302 || status == 405;
                });
    }
}
