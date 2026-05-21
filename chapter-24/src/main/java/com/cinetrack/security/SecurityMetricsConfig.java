package com.cinetrack.security;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;

/**
 * Registers custom Micrometer metrics that complement the event-driven counters
 * in {@link SecurityAuditListener}.
 *
 * The active-sessions gauge demonstrates how to expose a pull-based metric
 * (current state) alongside the push-based counters (accumulated events).
 * Alerting on the gauge catches session explosion from credential stuffing;
 * alerting on the counter rate catches brute-force spikes.
 *
 * {@link SessionRegistry} is a Spring Security bean that tracks all active
 * HTTP sessions. It requires session creation policy ALWAYS or IF_REQUIRED : 
 * the default for form-login applications. The gauge reads its size lazily
 * on each Prometheus scrape rather than on every session event.
 */
@Configuration
public class SecurityMetricsConfig {

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public Gauge activeSessionsGauge(MeterRegistry meterRegistry,
                                     SessionRegistry sessionRegistry) {
        return Gauge.builder("security.sessions.active",
                        sessionRegistry,
                        registry -> registry.getAllPrincipals().size())
                .description("Number of principals with at least one active HTTP session")
                .register(meterRegistry);
    }
}
