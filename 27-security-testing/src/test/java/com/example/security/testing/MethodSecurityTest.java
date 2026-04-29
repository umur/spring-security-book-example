package com.example.security.testing;

import com.example.security.testing.service.ResourceService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Method-level security testing reference.
 *
 * Demonstrates two approaches to testing @PreAuthorize:
 *
 * 1. Through the HTTP layer via MockMvc — end-to-end, includes filter chain
 * 2. Directly calling the Spring-proxied service bean — faster, no HTTP overhead,
 *    tests the security interceptor independently of the web layer.
 *
 * For direct service calls, the SecurityContext must be populated manually;
 * this is the equivalent of what .with(user(...)) does for MockMvc.
 */
@SpringBootTest
@AutoConfigureMockMvc
class MethodSecurityTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ResourceService resourceService;

    // =========================================================================
    // Via HTTP layer
    // =========================================================================

    @Nested
    @DisplayName("Via HTTP layer — filter chain + method security")
    class ViaHttp {

        @Test
        @DisplayName("USER accessing /api/user — 200 OK")
        void userEndpointAllowsUser() throws Exception {
            mockMvc.perform(get("/api/user").with(user("alice").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Hello, alice"));
        }

        @Test
        @DisplayName("USER accessing /api/admin — 403 Forbidden from filter chain")
        void adminEndpointDeniesUser() throws Exception {
            mockMvc.perform(get("/api/admin").with(user("alice").roles("USER")))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("ADMIN accessing /api/admin — 200 OK")
        void adminEndpointAllowsAdmin() throws Exception {
            mockMvc.perform(get("/api/admin").with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Admin resource"));
        }
    }

    // =========================================================================
    // Direct service calls — testing the AOP proxy directly
    // =========================================================================

    @Nested
    @DisplayName("Direct service call — AOP proxy enforcement")
    class DirectServiceCall {

        @Test
        @DisplayName("getPublicInfo() works without any SecurityContext")
        void publicMethodRequiresNoAuth() {
            SecurityContextHolder.clearContext();
            Map<String, String> result = resourceService.getPublicInfo();
            assertThat(result).containsEntry("status", "ok");
        }

        @Test
        @DisplayName("getUserResource() succeeds when USER is in SecurityContext")
        void userMethodSucceedsWithUserContext() {
            runAsUser("alice", "ROLE_USER", () -> {
                Map<String, Object> result = resourceService.getUserResource("alice");
                assertThat(result).containsEntry("message", "Hello, alice");
            });
        }

        @Test
        @DisplayName("getUserResource() throws security exception without auth")
        void userMethodThrowsWithoutAuth() {
            SecurityContextHolder.clearContext();
            // Without any authentication in the SecurityContext Spring Security throws
            // AuthenticationCredentialsNotFoundException (a subtype of AuthenticationException,
            // NOT AccessDeniedException). AccessDeniedException is only thrown when a principal
            // IS authenticated but lacks the required authority.
            assertThatThrownBy(() -> resourceService.getUserResource("anonymous"))
                    .isInstanceOf(org.springframework.security.core.AuthenticationException.class);
        }

        @Test
        @DisplayName("getAdminResource() succeeds when ADMIN is in SecurityContext")
        void adminMethodSucceedsWithAdminContext() {
            runAsUser("admin", "ROLE_ADMIN", () -> {
                Map<String, Object> result = resourceService.getAdminResource();
                assertThat(result).containsEntry("message", "Admin resource");
            });
        }

        @Test
        @DisplayName("getAdminResource() throws AccessDeniedException for USER role")
        void adminMethodThrowsForUserRole() {
            runAsUser("alice", "ROLE_USER", () ->
                    assertThatThrownBy(() -> resourceService.getAdminResource())
                            .isInstanceOf(AccessDeniedException.class));
        }

        // --- helper: sets up the SecurityContext for a single lambda invocation ---

        private void runAsUser(String username, String role, Runnable action) {
            var auth = UsernamePasswordAuthenticationToken.authenticated(
                    username, null,
                    List.of(new SimpleGrantedAuthority(role)));
            SecurityContextHolder.getContext().setAuthentication(auth);
            try {
                action.run();
            } finally {
                SecurityContextHolder.clearContext();
            }
        }
    }
}
