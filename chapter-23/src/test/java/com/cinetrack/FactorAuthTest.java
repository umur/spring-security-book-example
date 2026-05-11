package com.cinetrack;

import com.cinetrack.security.JwkConfig;
import com.cinetrack.security.SecurityConfig;
import com.cinetrack.subscription.SubscriptionController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that the subscription tier endpoint enforces {@code FACTOR_TOTP}
 * as a second-factor authorization requirement beyond a valid JWT.
 *
 * The pattern mirrors real step-up authentication: a user authenticates with
 * a password (or SSO), receives a standard JWT, then completes a TOTP
 * challenge. The authorization server re-issues the token with an additional
 * {@code FACTOR_TOTP} claim (or the application adds the authority to the
 * security context after verifying the TOTP code in a separate step).
 *
 * These tests use {@code jwt().authorities(...)} to simulate both states —
 * pre- and post-TOTP-challenge — without standing up a real MFA flow.
 */
@WebMvcTest(SubscriptionController.class)
@Import({SecurityConfig.class, JwkConfig.class})
class FactorAuthTest {

    @Autowired
    private MockMvc mockMvc;

    private static final String TIER_BODY = """
            {"tier":"PREMIUM"}
            """;

    @Test
    @DisplayName("JWT with only ROLE_USER cannot PUT /api/subscriptions/tier — 403")
    void jwtWithoutTotpFactor_returns403() throws Exception {
        mockMvc.perform(put("/api/subscriptions/tier")
                .with(jwt()
                    .authorities(new SimpleGrantedAuthority("ROLE_USER"))
                )
                .contentType(MediaType.APPLICATION_JSON)
                .content(TIER_BODY))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("JWT with ROLE_USER + FACTOR_TOTP can PUT /api/subscriptions/tier — 200")
    void jwtWithTotpFactor_returns200() throws Exception {
        mockMvc.perform(put("/api/subscriptions/tier")
                .with(jwt()
                    .authorities(
                        new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("FACTOR_TOTP")
                    )
                )
                .contentType(MediaType.APPLICATION_JSON)
                .content(TIER_BODY))
                .andExpect(status().isOk());
    }
}
