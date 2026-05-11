package com.cinetrack;

import com.cinetrack.security.SecurityAuditListener;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that authorization denial events are written to the in-memory
 * audit log by {@link SecurityAuditListener}.
 *
 * This test uses {@code @SpringBootTest} with {@code @AutoConfigureMockMvc}
 * so we get the full application context (the listener bean is present) while
 * still using the MockMvc convenience API. Authorization denied events fire
 * after authentication succeeds but before the response is sent, so MockMvc
 * captures them correctly.
 *
 * Scenario: Bob has {@code ROLE_USER} but {@code /api/admin/users} requires
 * {@code ROLE_ADMIN}. Spring Security fires an
 * {@link org.springframework.security.authorization.event.AuthorizationDeniedEvent}
 * that the listener appends to the audit log.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationEventTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SecurityAuditListener auditListener;

    @Autowired
    private MeterRegistry meterRegistry;

    @Test
    @DisplayName("Bob (ROLE_USER) denied from /api/admin/users — audit log contains one denial entry")
    void bobDeniedFromAdmin_auditLogContainsEntry() throws Exception {
        int auditSizeBefore = auditListener.getAuditLog().size();
        double counterBefore = denialCount();

        mockMvc.perform(get("/api/admin/users")
                .with(httpBasic("bob", "bob123")))
                .andExpect(status().isForbidden());

        List<SecurityAuditListener.AuditEntry> log = auditListener.getAuditLog();
        assertThat(log.size()).isGreaterThan(auditSizeBefore);

        SecurityAuditListener.AuditEntry denial = log.get(log.size() - 1);
        assertThat(denial.username()).isEqualTo("bob");
        assertThat(denial.event()).isEqualTo("AUTHORIZATION_DENIED");

        assertThat(denialCount()).isGreaterThan(counterBefore);
    }

    // ---- helpers --------------------------------------------------------

    private double denialCount() {
        try {
            return meterRegistry.find("security.authz.denied").counters().stream()
                    .mapToDouble(c -> c.count()).sum();
        } catch (Exception e) {
            return 0.0;
        }
    }
}
