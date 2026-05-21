package com.cinetrack;

import com.cinetrack.admin.AdminController;
import com.cinetrack.movie.MovieController;
import com.cinetrack.security.CineTrackPrincipal;
import com.cinetrack.security.JwkConfig;
import com.cinetrack.security.SecurityConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import java.util.List;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Demonstrates request-level authentication post-processors for MockMvc tests.
 *
 * In Spring Security 6+ (Spring Boot 3+), {@code SecurityContextHolderFilter}
 * replaced {@code SecurityContextPersistenceFilter}. The new filter reads the
 * security context from the repository at the START of each request, overwriting
 * any context set earlier by test execution listeners (the mechanism behind
 * {@code @WithMockUser}). As a result, annotation-based setup no longer works
 * in {@code @WebMvcTest} slices.
 *
 * The correct approach is to set authentication at the REQUEST level using
 * {@link org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors}:
 * <ul>
 *   <li>{@code user("alice").roles("USER")}: injects a {@code UserDetails}-backed
 *       authentication token for role-based access control tests.</li>
 *   <li>{@code authentication(token)}: injects any {@link Authentication}
 *       implementation, enabling domain-specific principals like
 *       {@link CineTrackPrincipal}.</li>
 * </ul>
 *
 * The {@link PrincipalController} inner class is a minimal endpoint wired just
 * for this test so we can assert on the principal's concrete type without
 * polluting the production controllers.
 */
@WebMvcTest({MovieController.class, AdminController.class, TestPrincipalController.class})
@Import({SecurityConfig.class, JwkConfig.class})
class WithMockUserTest {

    @Autowired
    private MockMvc mockMvc;

    // ---- user() post-processor tests -------------------------------------------

    @Test
    @DisplayName("user(roles=USER) can access /api/movies")
    void userRoleAccessesMovies_returns200() throws Exception {
        mockMvc.perform(get("/api/movies")
                        .with(user("alice").roles("USER")))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("user(roles=ADMIN) can access /api/admin/users")
    void adminRoleAccessesAdminUsers_returns200() throws Exception {
        mockMvc.perform(get("/api/admin/users")
                        .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("user(roles=USER) is forbidden from /api/admin/users")
    void userRoleForbiddenFromAdmin_returns403() throws Exception {
        mockMvc.perform(get("/api/admin/users")
                        .with(user("alice").roles("USER")))
                .andExpect(status().isForbidden());
    }

    // ---- authentication() post-processor with domain principal ----------------

    @Test
    @DisplayName("authentication() with CineTrackPrincipal(PREMIUM) is accessible in controller")
    void cineTrackUserPrincipalHasPremiumTier() throws Exception {
        Authentication auth = new UsernamePasswordAuthenticationToken(
                new CineTrackPrincipal("u99", "charlie@cinetrack.io", "PREMIUM"),
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        mockMvc.perform(get("/api/test/principal")
                        .with(authentication(auth)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("charlie@cinetrack.io"))
                .andExpect(jsonPath("$.subscriptionTier").value("PREMIUM"));
    }

    @Test
    @DisplayName("authentication() with default CineTrackPrincipal injects userId and tier")
    void cineTrackUserDefaultPrincipal() throws Exception {
        Authentication auth = new UsernamePasswordAuthenticationToken(
                new CineTrackPrincipal("u1", "test@cinetrack.io", "FREE"),
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        mockMvc.perform(get("/api/test/principal")
                        .with(authentication(auth)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("u1"))
                .andExpect(jsonPath("$.subscriptionTier").value("FREE"));
    }

}
