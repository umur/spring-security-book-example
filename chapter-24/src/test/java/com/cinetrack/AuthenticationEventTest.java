package com.cinetrack;

import com.cinetrack.security.SecurityAuditListener;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that authentication events are captured as Micrometer counter
 * increments by {@link SecurityAuditListener}.
 *
 * Uses @SpringBootTest with @AutoConfigureMockMvc so the full application
 * context loads (listener bean present, real filter chain active) while
 * MockMvc drives requests without requiring a random port.
 *
 * Counters accumulate across the test class. We read values before and after
 * each action and assert on the delta so tests are order-independent.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthenticationEventTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private MeterRegistry meterRegistry;

    @Test
    @DisplayName("Failed login increments auth.failures counter")
    void failedLogin_incrementsFailureCounter() throws Exception {
        double before = failureCount();

        mockMvc.perform(get("/api/movies")
                .with(httpBasic("alice", "wrong-password")))
                .andExpect(status().isUnauthorized());

        assertThat(failureCount()).isGreaterThan(before);
    }

    @Test
    @DisplayName("Successful login increments auth.successes counter")
    void successfulLogin_incrementsSuccessCounter() throws Exception {
        double before = successCount();

        mockMvc.perform(get("/api/movies")
                .with(httpBasic("alice", "alice123")))
                .andExpect(status().isOk());

        assertThat(successCount()).isGreaterThan(before);
    }

    // ---- helpers --------------------------------------------------------

    private double failureCount() {
        try {
            return meterRegistry.find("security.auth.failure").counters().stream()
                    .mapToDouble(c -> c.count()).sum();
        } catch (Exception e) {
            return 0.0;
        }
    }

    private double successCount() {
        try {
            return meterRegistry.find("security.auth.success").counters().stream()
                    .mapToDouble(c -> c.count()).sum();
        } catch (Exception e) {
            return 0.0;
        }
    }
}
