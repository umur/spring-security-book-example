package com.cinetrack.authorization;

import com.cinetrack.catalog.CatalogController;
import com.cinetrack.security.SecurityConfig;
import com.cinetrack.security.SubscriptionTierAuthorizationManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that {@link SubscriptionTierAuthorizationManager} correctly gates
 * premium and standard catalog endpoints.
 *
 * {@code @WebMvcTest} loads only the web layer and the explicitly imported
 * configuration, keeping the test fast and focused on the URL-level authorization
 * logic rather than the full application context.
 */
@WebMvcTest(CatalogController.class)
@Import({SecurityConfig.class, SubscriptionTierAuthorizationManager.class})
class AuthorizationManagerTest {

    @Autowired
    private MockMvc mockMvc;

    // -------------------------------------------------------------------------
    // Premium endpoint
    // -------------------------------------------------------------------------

    @Test
    void alice_withTierPremium_canAccessPremiumMovies() throws Exception {
        mockMvc.perform(get("/api/catalog/movies/premium")
                        .with(user("alice").authorities(
                                new SimpleGrantedAuthority("ROLE_USER"),
                                new SimpleGrantedAuthority("TIER_PREMIUM"))))
                .andExpect(status().isOk());
    }

    @Test
    void bob_withTierBasic_cannotAccessPremiumMovies_returns403() throws Exception {
        mockMvc.perform(get("/api/catalog/movies/premium")
                        .with(user("bob").authorities(
                                new SimpleGrantedAuthority("ROLE_USER"),
                                new SimpleGrantedAuthority("TIER_BASIC"))))
                .andExpect(status().isForbidden());
    }

    // -------------------------------------------------------------------------
    // Standard endpoint: both tiers allowed
    // -------------------------------------------------------------------------

    @Test
    void alice_canAccessStandardMovies() throws Exception {
        mockMvc.perform(get("/api/catalog/movies")
                        .with(user("alice").authorities(
                                new SimpleGrantedAuthority("ROLE_USER"),
                                new SimpleGrantedAuthority("TIER_PREMIUM"))))
                .andExpect(status().isOk());
    }

    @Test
    void bob_canAccessStandardMovies() throws Exception {
        mockMvc.perform(get("/api/catalog/movies")
                        .with(user("bob").authorities(
                                new SimpleGrantedAuthority("ROLE_USER"),
                                new SimpleGrantedAuthority("TIER_BASIC"))))
                .andExpect(status().isOk());
    }
}
