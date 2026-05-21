package com.cinetrack.security;

import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that security events are translated into Micrometer counter increments.
 *
 * Uses @SpringBootTest so the full application context loads: the
 * SecurityAuditListener bean is present and wired to the MeterRegistry. MockMvc
 * drives HTTP requests through the complete filter chain, firing real
 * Spring Security events.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityAuditListenerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private MeterRegistry meterRegistry;

    @Test
    void successfulLogin_incrementsSuccessCounter() throws Exception {
        double before = successCount();

        mockMvc.perform(get("/api/catalog/movies")
                .with(httpBasic("alice", "alice123")))
                .andExpect(status().isOk());

        assertThat(successCount()).isGreaterThan(before);
    }

    @Test
    void failedLogin_incrementsFailureCounter() throws Exception {
        double before = failureCount();

        mockMvc.perform(get("/api/catalog/movies")
                .with(httpBasic("admin", "wrong")))
                .andExpect(status().isUnauthorized());

        assertThat(failureCount()).isGreaterThan(before);
    }

    @Test
    void deniedAccess_incrementsDeniedCounter() throws Exception {
        double before = deniedCount();

        // bob has ROLE_USER; /api/admin/** requires ROLE_ADMIN
        mockMvc.perform(get("/api/admin/users")
                .with(httpBasic("bob", "bob123")))
                .andExpect(status().isForbidden());

        assertThat(deniedCount()).isGreaterThan(before);
    }

    // ---- helpers --------------------------------------------------------

    private double successCount() {
        return meterRegistry.find("security.auth.success").counters().stream()
                .mapToDouble(c -> c.count()).sum();
    }

    private double failureCount() {
        return meterRegistry.find("security.auth.failure").counters().stream()
                .mapToDouble(c -> c.count()).sum();
    }

    private double deniedCount() {
        return meterRegistry.find("security.authz.denied").counters().stream()
                .mapToDouble(c -> c.count()).sum();
    }
}
