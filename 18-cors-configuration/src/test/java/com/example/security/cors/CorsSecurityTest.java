package com.example.security.cors;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static com.example.security.cors.config.SecurityConfig.TRUSTED_ORIGIN;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class CorsSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    // -------------------------------------------------------------------------
    // Preflight (OPTIONS) tests
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Preflight OPTIONS requests")
    class PreflightRequests {

        @Test
        @DisplayName("OPTIONS /api/public from any origin returns 200 with CORS headers")
        void preflightPublicEndpointReturnsOk() throws Exception {
            mockMvc.perform(options("/api/public")
                            .header(HttpHeaders.ORIGIN, "https://random.example.com")
                            .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET"))
                    .andExpect(status().isOk())
                    .andExpect(header().exists(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN))
                    .andExpect(header().exists(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS));
        }

        @Test
        @DisplayName("OPTIONS /api/data from trusted origin returns correct CORS headers")
        void preflightRestrictedEndpointFromTrustedOriginReturnsOk() throws Exception {
            mockMvc.perform(options("/api/data")
                            .header(HttpHeaders.ORIGIN, TRUSTED_ORIGIN)
                            .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                            .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "Authorization,Content-Type"))
                    .andExpect(status().isOk())
                    .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, TRUSTED_ORIGIN))
                    .andExpect(header().exists(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS));
        }

        @Test
        @DisplayName("OPTIONS /api/data with non-allowed method returns no CORS allow-origin header")
        void preflightWithNonAllowedMethodIsRejected() throws Exception {
            // DELETE is not in the allowed methods for /api/data
            mockMvc.perform(options("/api/data")
                            .header(HttpHeaders.ORIGIN, TRUSTED_ORIGIN)
                            .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "DELETE"))
                    .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
        }
    }

    // -------------------------------------------------------------------------
    // Public endpoint CORS
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Public endpoint CORS (any origin)")
    class PublicEndpointCors {

        @Test
        @DisplayName("GET /api/public from any origin includes Access-Control-Allow-Origin")
        void publicEndpointAllowsAnyOrigin() throws Exception {
            mockMvc.perform(get("/api/public")
                            .header(HttpHeaders.ORIGIN, "https://anything.example.com"))
                    .andExpect(status().isOk())
                    .andExpect(header().exists(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
        }

        @Test
        @DisplayName("GET /api/public without authentication succeeds (permitAll)")
        void publicEndpointIsPermitAll() throws Exception {
            mockMvc.perform(get("/api/public")
                            .header(HttpHeaders.ORIGIN, "https://anything.example.com"))
                    .andExpect(status().isOk());
        }
    }

    // -------------------------------------------------------------------------
    // Restricted endpoint CORS
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Restricted endpoint CORS (specific origins)")
    class RestrictedEndpointCors {

        @Test
        @DisplayName("GET /api/data from trusted origin includes Access-Control-Allow-Origin")
        void restrictedEndpointAllowsTrustedOrigin() throws Exception {
            mockMvc.perform(get("/api/data")
                            .with(user("alice").roles("USER"))
                            .header(HttpHeaders.ORIGIN, TRUSTED_ORIGIN))
                    .andExpect(status().isOk())
                    .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, TRUSTED_ORIGIN));
        }

        @Test
        @DisplayName("GET /api/data from disallowed origin does NOT include Access-Control-Allow-Origin")
        void restrictedEndpointBlocksUntrustedOrigin() throws Exception {
            mockMvc.perform(get("/api/data")
                            .with(user("alice").roles("USER"))
                            .header(HttpHeaders.ORIGIN, "https://evil.example.com"))
                    .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
        }

        @Test
        @DisplayName("POST /api/data from trusted origin succeeds with correct CORS headers")
        void restrictedEndpointPostFromTrustedOrigin() throws Exception {
            mockMvc.perform(post("/api/data")
                            .with(user("alice").roles("USER"))
                            .header(HttpHeaders.ORIGIN, TRUSTED_ORIGIN)
                            .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"key\":\"value\"}"))
                    .andExpect(status().isOk())
                    .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, TRUSTED_ORIGIN));
        }

        @Test
        @DisplayName("GET /api/data without authentication returns 401")
        void restrictedEndpointRequiresAuthentication() throws Exception {
            mockMvc.perform(get("/api/data")
                            .header(HttpHeaders.ORIGIN, TRUSTED_ORIGIN))
                    .andExpect(status().isUnauthorized());
        }
    }
}
