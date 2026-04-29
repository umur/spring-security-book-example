package com.example.security.testing;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Security response headers testing reference.
 *
 * Spring Security automatically adds a set of defensive HTTP headers to every
 * response when headers() is configured. This test class verifies each header
 * is present and contains the expected directives.
 *
 * Headers verified:
 *   X-Content-Type-Options: nosniff
 *   X-Frame-Options: DENY
 *   Strict-Transport-Security: max-age=…; includeSubDomains
 *   Content-Security-Policy: default-src 'self'
 *   Referrer-Policy: strict-origin-when-cross-origin
 *   Permissions-Policy: camera=(), microphone=()
 *   Cache-Control: no-cache, no-store (Spring Security default)
 */
@SpringBootTest
@AutoConfigureMockMvc
class HeadersTest {

    @Autowired
    MockMvc mockMvc;

    // =========================================================================
    // X-Content-Type-Options
    // =========================================================================

    @Nested
    @DisplayName("X-Content-Type-Options")
    class XContentTypeOptions {

        @Test
        @DisplayName("Response contains X-Content-Type-Options: nosniff")
        void nosniff() throws Exception {
            mockMvc.perform(get("/api/user").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().string("X-Content-Type-Options", "nosniff"));
        }
    }

    // =========================================================================
    // X-Frame-Options
    // =========================================================================

    @Nested
    @DisplayName("X-Frame-Options")
    class XFrameOptions {

        @Test
        @DisplayName("Response contains X-Frame-Options: DENY")
        void deny() throws Exception {
            mockMvc.perform(get("/api/user").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().string("X-Frame-Options", "DENY"));
        }

        @Test
        @DisplayName("Public endpoint also includes X-Frame-Options")
        void publicEndpointHasFrameOptions() throws Exception {
            mockMvc.perform(get("/api/public"))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("X-Frame-Options"));
        }
    }

    // =========================================================================
    // Strict-Transport-Security (HSTS)
    // =========================================================================

    @Nested
    @DisplayName("Strict-Transport-Security (HSTS)")
    class Hsts {

        @Test
        @DisplayName("Response contains HSTS header")
        void hstsPresent() throws Exception {
            mockMvc.perform(get("/api/user").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("Strict-Transport-Security"));
        }

        @Test
        @DisplayName("HSTS header includes max-age and includeSubDomains")
        void hstsDirectives() throws Exception {
            mockMvc.perform(get("/api/user").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Strict-Transport-Security",
                            containsString("max-age=")))
                    .andExpect(header().string("Strict-Transport-Security",
                            containsString("includeSubDomains")));
        }
    }

    // =========================================================================
    // Content-Security-Policy (CSP)
    // =========================================================================

    @Nested
    @DisplayName("Content-Security-Policy")
    class Csp {

        @Test
        @DisplayName("Response contains CSP header")
        void cspPresent() throws Exception {
            mockMvc.perform(get("/api/user").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("Content-Security-Policy"));
        }

        @Test
        @DisplayName("CSP header contains default-src directive")
        void cspDefaultSrc() throws Exception {
            mockMvc.perform(get("/api/user").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Content-Security-Policy",
                            containsString("default-src")));
        }
    }

    // =========================================================================
    // Referrer-Policy
    // =========================================================================

    @Nested
    @DisplayName("Referrer-Policy")
    class ReferrerPolicy {

        @Test
        @DisplayName("Response contains Referrer-Policy header")
        void referrerPolicyPresent() throws Exception {
            mockMvc.perform(get("/api/user").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("Referrer-Policy"));
        }

        @Test
        @DisplayName("Referrer-Policy is strict-origin-when-cross-origin")
        void referrerPolicyValue() throws Exception {
            mockMvc.perform(get("/api/user").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Referrer-Policy",
                            containsString("strict-origin-when-cross-origin")));
        }
    }

    // =========================================================================
    // Permissions-Policy
    // =========================================================================

    @Nested
    @DisplayName("Permissions-Policy")
    class PermissionsPolicy {

        @Test
        @DisplayName("Response contains Permissions-Policy header")
        void permissionsPolicyPresent() throws Exception {
            mockMvc.perform(get("/api/user").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("Permissions-Policy"));
        }

        @Test
        @DisplayName("Permissions-Policy disables camera and microphone")
        void permissionsPolicyDisablesSensors() throws Exception {
            mockMvc.perform(get("/api/user").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Permissions-Policy",
                            containsString("camera=()")))
                    .andExpect(header().string("Permissions-Policy",
                            containsString("microphone=()")));
        }
    }

    // =========================================================================
    // Cache-Control
    // =========================================================================

    @Nested
    @DisplayName("Cache-Control")
    class CacheControl {

        @Test
        @DisplayName("Response contains Cache-Control: no-cache, no-store")
        void cacheControlPresent() throws Exception {
            mockMvc.perform(get("/api/user").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Cache-Control",
                            containsString("no-cache")))
                    .andExpect(header().string("Cache-Control",
                            containsString("no-store")));
        }
    }

    // =========================================================================
    // All headers present on a single request
    // =========================================================================

    @Nested
    @DisplayName("All security headers present on single response")
    class AllHeaders {

        @Test
        @DisplayName("All expected security headers are present on /api/user")
        void allHeadersPresent() throws Exception {
            mockMvc.perform(get("/api/user").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("X-Content-Type-Options"))
                    .andExpect(header().exists("X-Frame-Options"))
                    .andExpect(header().exists("Strict-Transport-Security"))
                    .andExpect(header().exists("Content-Security-Policy"))
                    .andExpect(header().exists("Referrer-Policy"))
                    .andExpect(header().exists("Permissions-Policy"))
                    .andExpect(header().exists("Cache-Control"));
        }
    }
}
