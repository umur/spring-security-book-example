package com.cinetrack.authorization;

import com.cinetrack.security.SecurityConfig;
import com.cinetrack.security.SubscriptionTierAuthorizationManager;
import com.cinetrack.subscription.SubscriptionController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that the {@code FACTOR_TOTP} step-up authority is required for
 * subscription tier changes.
 *
 * This models a common pattern where a second factor (TOTP, WebAuthn, etc.)
 * is represented as an authority granted after a successful step-up challenge.
 * The filter chain checks for that authority: the controller sees only the
 * requests that passed.
 */
@WebMvcTest(SubscriptionController.class)
@Import({SecurityConfig.class, SubscriptionTierAuthorizationManager.class})
class FactorAuthorizationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void userWithoutTotp_cannotChangeTier_returns403() throws Exception {
        mockMvc.perform(put("/api/subscriptions/tier")
                        .param("tier", "PREMIUM")
                        .with(user("alice")
                                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                                             new SimpleGrantedAuthority("TIER_PREMIUM"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void userWithTotp_canChangeTier_returns200() throws Exception {
        mockMvc.perform(put("/api/subscriptions/tier")
                        .param("tier", "PREMIUM")
                        .with(user("alice")
                                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                                             new SimpleGrantedAuthority("TIER_PREMIUM"),
                                             new SimpleGrantedAuthority("FACTOR_TOTP"))))
                .andExpect(status().isOk());
    }
}
