package com.example.security.headers;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityHeadersTest {

    @Autowired
    private MockMvc mockMvc;

    // -------------------------------------------------------------------------
    // X-Content-Type-Options
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("X-Content-Type-Options header")
    class XContentTypeOptions {

        @Test
        @DisplayName("Response contains X-Content-Type-Options: nosniff")
        void containsXContentTypeOptions() throws Exception {
            mockMvc.perform(get("/api/info").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().string("X-Content-Type-Options", "nosniff"));
        }
    }

    // -------------------------------------------------------------------------
    // X-Frame-Options
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("X-Frame-Options header")
    class XFrameOptions {

        @Test
        @DisplayName("Response contains X-Frame-Options: DENY")
        void containsXFrameOptions() throws Exception {
            mockMvc.perform(get("/api/info").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().string("X-Frame-Options", "DENY"));
        }
    }

    // -------------------------------------------------------------------------
    // Strict-Transport-Security
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Strict-Transport-Security header")
    class StrictTransportSecurity {

        @Test
        @DisplayName("Response contains Strict-Transport-Security header")
        void containsHsts() throws Exception {
            mockMvc.perform(get("/api/info").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("Strict-Transport-Security"));
        }

        @Test
        @DisplayName("HSTS header includes max-age and includeSubDomains")
        void hstsContainsMaxAgeAndSubDomains() throws Exception {
            mockMvc.perform(get("/api/info").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Strict-Transport-Security",
                            org.hamcrest.Matchers.containsString("max-age=")))
                    .andExpect(header().string("Strict-Transport-Security",
                            org.hamcrest.Matchers.containsString("includeSubDomains")));
        }
    }

    // -------------------------------------------------------------------------
    // Content-Security-Policy
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Content-Security-Policy header")
    class ContentSecurityPolicy {

        @Test
        @DisplayName("Response contains Content-Security-Policy header")
        void containsCsp() throws Exception {
            mockMvc.perform(get("/api/info").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("Content-Security-Policy"));
        }

        @Test
        @DisplayName("CSP header contains default-src directive")
        void cspContainsDefaultSrc() throws Exception {
            mockMvc.perform(get("/api/info").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Content-Security-Policy",
                            org.hamcrest.Matchers.containsString("default-src")));
        }
    }

    // -------------------------------------------------------------------------
    // Referrer-Policy
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Referrer-Policy header")
    class ReferrerPolicy {

        @Test
        @DisplayName("Response contains Referrer-Policy header")
        void containsReferrerPolicy() throws Exception {
            mockMvc.perform(get("/api/info").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("Referrer-Policy"));
        }
    }

    // -------------------------------------------------------------------------
    // Permissions-Policy
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Permissions-Policy header")
    class PermissionsPolicy {

        @Test
        @DisplayName("Response contains Permissions-Policy header")
        void containsPermissionsPolicy() throws Exception {
            mockMvc.perform(get("/api/info").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("Permissions-Policy"));
        }

        @Test
        @DisplayName("Permissions-Policy disables camera and microphone")
        void permissionsPolicyDisablesSensitiveFeatures() throws Exception {
            mockMvc.perform(get("/api/info").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Permissions-Policy",
                            org.hamcrest.Matchers.containsString("camera=()")))
                    .andExpect(header().string("Permissions-Policy",
                            org.hamcrest.Matchers.containsString("microphone=()")));
        }
    }

    // -------------------------------------------------------------------------
    // Cache-Control
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Cache-Control header")
    class CacheControl {

        @Test
        @DisplayName("Response contains Cache-Control: no-cache, no-store")
        void containsCacheControl() throws Exception {
            mockMvc.perform(get("/api/info").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Cache-Control",
                            org.hamcrest.Matchers.containsString("no-cache")))
                    .andExpect(header().string("Cache-Control",
                            org.hamcrest.Matchers.containsString("no-store")));
        }
    }

    // -------------------------------------------------------------------------
    // /api/headers endpoint
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("/api/headers endpoint")
    class HeadersEndpoint {

        @Test
        @DisplayName("GET /api/headers returns 200 with all security headers present")
        void headersEndpointReturnsOkWithSecurityHeaders() throws Exception {
            mockMvc.perform(get("/api/headers").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("X-Content-Type-Options"))
                    .andExpect(header().exists("X-Frame-Options"))
                    .andExpect(header().exists("Strict-Transport-Security"))
                    .andExpect(header().exists("Content-Security-Policy"))
                    .andExpect(header().exists("Referrer-Policy"))
                    .andExpect(header().exists("Permissions-Policy"))
                    .andExpect(header().exists("Cache-Control"));
        }

        @Test
        @DisplayName("GET /api/headers without auth returns 401")
        void headersEndpointUnauthenticatedReturns401() throws Exception {
            mockMvc.perform(get("/api/headers"))
                    .andExpect(status().isUnauthorized());
        }
    }
}
