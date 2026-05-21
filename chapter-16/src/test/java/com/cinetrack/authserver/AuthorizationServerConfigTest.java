package com.cinetrack.authserver;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Base64;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Smoke tests for standard authorization server well-known endpoints.
 *
 * These tests verify the server starts correctly and exposes the endpoints
 * that clients and resource servers depend on at boot time.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthorizationServerConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void jwksEndpoint_returns200() throws Exception {
        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray());
    }

    @Test
    void openidConfiguration_returns200() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("http://localhost:9000"));
    }

    @Test
    void pushedAuthorizationEndpoint_requiresAuthentication() throws Exception {
        // PAR requires client authentication. Invalid credentials must be rejected with 401.
        String badCredentials = Base64.getEncoder()
                .encodeToString("unknown-client:bad-secret".getBytes());
        mockMvc.perform(post("/oauth2/par")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(HttpHeaders.AUTHORIZATION, "Basic " + badCredentials)
                        .param("response_type", "code")
                        .param("client_id", "unknown-client"))
                .andExpect(status().isUnauthorized());
    }
}
