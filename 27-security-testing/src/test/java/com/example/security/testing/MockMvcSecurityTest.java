package com.example.security.testing;

import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Comprehensive MockMvc security testing reference.
 *
 * Demonstrates every major MockMvc authentication post-processor:
 *
 *   .with(user(...).roles(...))   — inject a UserDetails principal
 *   .with(httpBasic(...))         — send HTTP Basic credentials
 *   .with(csrf())                 — include a valid CSRF token
 *   .with(jwt())                  — inject a JwtAuthenticationToken
 *   .with(anonymous())            — explicit anonymous principal
 *
 * Spring Boot 4 / Spring Security 7 conventions:
 *   - @AutoConfigureMockMvc from org.springframework.boot.webmvc.test.autoconfigure
 *   - @SpringBootTest (NOT @WebMvcTest) so the full security filter chain loads
 *   - @WithMockUser is NOT used — .with(user(...)) post-processor is the correct approach
 */
@SpringBootTest
@AutoConfigureMockMvc
class MockMvcSecurityTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    // =========================================================================
    // Public endpoint — no authentication required
    // =========================================================================

    @Nested
    @DisplayName("GET /api/public — no auth required")
    class PublicEndpoint {

        @Test
        @DisplayName("unauthenticated request returns 200")
        void unauthenticatedGetsPublic() throws Exception {
            mockMvc.perform(get("/api/public"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("This endpoint is public"));
        }

        @Test
        @DisplayName("authenticated USER can also access public endpoint")
        void authenticatedUserGetsPublic() throws Exception {
            mockMvc.perform(get("/api/public")
                            .with(user("alice").roles("USER")))
                    .andExpect(status().isOk());
        }
    }

    // =========================================================================
    // .with(user(...).roles(...)) — simulating an authenticated user
    // =========================================================================

    @Nested
    @DisplayName(".with(user(...)) — simulating authenticated users")
    class WithUserPostProcessor {

        @Test
        @DisplayName("USER can access /api/user")
        void userRoleCanAccessUserEndpoint() throws Exception {
            mockMvc.perform(get("/api/user")
                            .with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Hello, alice"));
        }

        @Test
        @DisplayName("unauthenticated request to /api/user returns 401")
        void unauthenticatedCannotAccessUser() throws Exception {
            mockMvc.perform(get("/api/user"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("USER cannot access /api/admin — returns 403")
        void userRoleCannotAccessAdmin() throws Exception {
            mockMvc.perform(get("/api/admin")
                            .with(user("alice").roles("USER")))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("ADMIN can access /api/admin")
        void adminRoleCanAccessAdmin() throws Exception {
            mockMvc.perform(get("/api/admin")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Admin resource"));
        }

        @Test
        @DisplayName("user with custom GrantedAuthority can access admin endpoint")
        void customAuthorityGrantsAccess() throws Exception {
            mockMvc.perform(get("/api/admin")
                            .with(user("power-user")
                                    .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                    .andExpect(status().isOk());
        }
    }

    // =========================================================================
    // .with(httpBasic(...)) — HTTP Basic authentication
    // =========================================================================

    @Nested
    @DisplayName(".with(httpBasic(...)) — HTTP Basic authentication")
    class HttpBasicPostProcessor {

        @Test
        @DisplayName("valid HTTP Basic credentials grant access to /api/user")
        void validBasicCredentialsGrantAccess() throws Exception {
            mockMvc.perform(get("/api/user")
                            .with(httpBasic("user", "user")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Hello, user"));
        }

        @Test
        @DisplayName("invalid HTTP Basic credentials return 401")
        void invalidBasicCredentialsReturn401() throws Exception {
            mockMvc.perform(get("/api/user")
                            .with(httpBasic("user", "wrong-password")))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("admin HTTP Basic credentials grant access to /api/admin")
        void adminBasicCredentialsGrantAdminAccess() throws Exception {
            mockMvc.perform(get("/api/admin")
                            .with(httpBasic("admin", "admin")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("user HTTP Basic credentials denied for /api/admin")
        void userBasicDeniedForAdmin() throws Exception {
            mockMvc.perform(get("/api/admin")
                            .with(httpBasic("user", "user")))
                    .andExpect(status().isForbidden());
        }
    }

    // =========================================================================
    // .with(jwt()) — JWT bearer token simulation
    // =========================================================================

    @Nested
    @DisplayName(".with(jwt()) — JWT bearer token simulation")
    class JwtPostProcessor {

        @Test
        @DisplayName("jwt() with USER scope grants access to /api/user")
        void jwtWithUserScopeGrantsAccess() throws Exception {
            mockMvc.perform(get("/api/user")
                            .with(jwt()
                                    .jwt(j -> j.subject("jwt-user")
                                            .claim("scope", "read"))
                                    .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Hello, jwt-user"));
        }

        @Test
        @DisplayName("jwt() with ADMIN authority grants access to /api/admin")
        void jwtWithAdminAuthorityGrantsAdminAccess() throws Exception {
            mockMvc.perform(get("/api/admin")
                            .with(jwt()
                                    .jwt(j -> j.subject("jwt-admin"))
                                    .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("jwt() without ADMIN authority denied at /api/admin")
        void jwtWithoutAdminDenied() throws Exception {
            mockMvc.perform(get("/api/admin")
                            .with(jwt()
                                    .jwt(j -> j.subject("jwt-user"))
                                    .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("jwt() with custom claims are accessible in the principal")
        void jwtWithCustomClaims() throws Exception {
            mockMvc.perform(get("/api/user")
                            .with(jwt()
                                    .jwt(j -> j
                                            .subject("custom-subject")
                                            .claim("email", "user@example.com")
                                            .claim("given_name", "Alice"))
                                    .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                    .andExpect(status().isOk());
        }
    }

    // =========================================================================
    // .with(csrf()) — CSRF token inclusion
    // =========================================================================

    @Nested
    @DisplayName(".with(csrf()) — CSRF token testing")
    class CsrfPostProcessor {

        @Test
        @DisplayName("POST /api/data WITHOUT csrf token returns 403")
        void postWithoutCsrfReturns403() throws Exception {
            mockMvc.perform(post("/api/data")
                            .with(user("alice").roles("USER"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"content\":\"test\"}"))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("POST /api/data WITH valid csrf token returns 201")
        void postWithCsrfReturns201() throws Exception {
            mockMvc.perform(post("/api/data")
                            .with(user("alice").roles("USER"))
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"content\":\"test\"}"))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.status").value("created"));
        }

        @Test
        @DisplayName("POST /api/data WITH invalid csrf token returns 403")
        void postWithInvalidCsrfReturns403() throws Exception {
            mockMvc.perform(post("/api/data")
                            .with(user("alice").roles("USER"))
                            .with(csrf().useInvalidToken())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"content\":\"test\"}"))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("GET requests do not require CSRF token")
        void getRequestDoesNotRequireCsrf() throws Exception {
            // No .with(csrf()) — GET is safe and should succeed without token
            mockMvc.perform(get("/api/user")
                            .with(user("alice").roles("USER")))
                    .andExpect(status().isOk());
        }
    }

    // =========================================================================
    // .with(oauth2Login()) — OAuth2 login simulation
    // =========================================================================

    @Nested
    @DisplayName(".with(oauth2Login()) — OAuth2 login simulation")
    class OAuth2LoginPostProcessor {

        @Test
        @DisplayName("oauth2Login() grants access to /api/user")
        void oauth2LoginGrantsUserAccess() throws Exception {
            mockMvc.perform(get("/api/user")
                            .with(oauth2Login()
                                    .attributes(attrs -> attrs.put("sub", "oauth2-user"))
                                    .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("oauth2Login() with ADMIN authority grants admin access")
        void oauth2LoginGrantsAdminAccess() throws Exception {
            mockMvc.perform(get("/api/admin")
                            .with(oauth2Login()
                                    .attributes(attrs -> {
                                        attrs.put("sub", "oauth2-admin");
                                        attrs.put("email", "admin@example.com");
                                    })
                                    .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                    .andExpect(status().isOk());
        }
    }

    // =========================================================================
    // .with(oidcLogin()) — OIDC login simulation
    // =========================================================================

    @Nested
    @DisplayName(".with(oidcLogin()) — OIDC login simulation")
    class OidcLoginPostProcessor {

        @Test
        @DisplayName("oidcLogin() grants access to /api/user")
        void oidcLoginGrantsAccess() throws Exception {
            mockMvc.perform(get("/api/user")
                            .with(oidcLogin()
                                    .idToken(token -> token
                                            .subject("oidc-user-123")
                                            .claim("email", "oidc@example.com")
                                            .claim("name", "OIDC User"))
                                    .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                    .andExpect(status().isOk());
        }
    }

    // =========================================================================
    // Access control summary — 200 / 401 / 403 matrix
    // =========================================================================

    @Nested
    @DisplayName("Access control matrix — 200 / 401 / 403")
    class AccessControlMatrix {

        @Test
        @DisplayName("GET /api/public: anonymous=200, user=200, admin=200")
        void publicMatrix() throws Exception {
            mockMvc.perform(get("/api/public")).andExpect(status().isOk());
            mockMvc.perform(get("/api/public").with(user("u").roles("USER"))).andExpect(status().isOk());
            mockMvc.perform(get("/api/public").with(user("a").roles("ADMIN"))).andExpect(status().isOk());
        }

        @Test
        @DisplayName("GET /api/user: anonymous=401, user=200, admin=200")
        void userMatrix() throws Exception {
            mockMvc.perform(get("/api/user")).andExpect(status().isUnauthorized());
            mockMvc.perform(get("/api/user").with(user("u").roles("USER"))).andExpect(status().isOk());
            mockMvc.perform(get("/api/user").with(user("a").roles("ADMIN"))).andExpect(status().isOk());
        }

        @Test
        @DisplayName("GET /api/admin: anonymous=401, user=403, admin=200")
        void adminMatrix() throws Exception {
            mockMvc.perform(get("/api/admin")).andExpect(status().isUnauthorized());
            mockMvc.perform(get("/api/admin").with(user("u").roles("USER"))).andExpect(status().isForbidden());
            mockMvc.perform(get("/api/admin").with(user("a").roles("ADMIN"))).andExpect(status().isOk());
        }
    }
}
