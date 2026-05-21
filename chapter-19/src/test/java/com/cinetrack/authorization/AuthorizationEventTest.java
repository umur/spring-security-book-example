package com.cinetrack.authorization;

import com.cinetrack.security.SecurityAuditListener;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that a denied request causes {@code AuthorizationDeniedEvent} to be
 * published and recorded by {@link SecurityAuditListener}.
 *
 * {@code @SpringBootTest} with {@code @AutoConfigureMockMvc} loads the full
 * application context: including the event infrastructure: so the listener
 * bean receives real events published by the authorization filter.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationEventTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SecurityAuditListener auditListener;

    @BeforeEach
    void clearDenials() {
        auditListener.clear();
    }

    @Test
    void deniedRequest_publishesAuthorizationDeniedEvent() throws Exception {
        // Bob (TIER_BASIC) attempts to access the premium endpoint: denied.
        mockMvc.perform(get("/api/catalog/movies/premium")
                        .with(user("bob")
                                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                                             new SimpleGrantedAuthority("TIER_BASIC"))))
                .andExpect(status().isForbidden());

        assertThat(auditListener.getDenials()).isNotEmpty();
    }

    @Test
    void allowedRequest_doesNotPublishDeniedEvent() throws Exception {
        // Alice (TIER_PREMIUM) accesses the premium endpoint: allowed.
        mockMvc.perform(get("/api/catalog/movies/premium")
                        .with(user("alice")
                                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                                             new SimpleGrantedAuthority("TIER_PREMIUM"))))
                .andExpect(status().isOk());

        assertThat(auditListener.getDenials()).isEmpty();
    }

    @Test
    void deniedRequest_recordsPrincipalInEvent() throws Exception {
        mockMvc.perform(get("/api/catalog/movies/premium")
                        .with(user("bob")
                                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                                             new SimpleGrantedAuthority("TIER_BASIC"))))
                .andExpect(status().isForbidden());

        assertThat(auditListener.getDenials()).hasSize(1);
        // The listener resolves the principal name eagerly at event time so we
        // can assert it here, after the request thread has completed.
        assertThat(auditListener.getDeniedPrincipalNames()).containsExactly("bob");
    }
}
