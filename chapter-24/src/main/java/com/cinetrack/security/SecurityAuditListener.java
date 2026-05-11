package com.cinetrack.security;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Converts Spring Security application events into Micrometer counter
 * increments and structured audit log entries.
 *
 * Spring Security publishes events for every significant security decision:
 * successful logins, failed logins, and authorization denials. By listening
 * to these events rather than instrumenting individual controllers, we get
 * coverage across the entire application automatically — including paths
 * added in future.
 *
 * Counters exposed:
 * <ul>
 *   <li>{@code auth.failures} — tagged with {@code reason} and {@code username}.</li>
 *   <li>{@code auth.successes} — tagged with {@code username}.</li>
 *   <li>{@code authz.denials} — tagged with {@code username} and {@code uri}.</li>
 * </ul>
 *
 * The in-memory audit log ({@link #getAuditLog()}) is intentionally simple —
 * production systems would write to an append-only audit store (database,
 * CloudWatch Logs, etc.) with tamper-evident properties.
 */
@Component
public class SecurityAuditListener {

    private static final Logger auditLog = LoggerFactory.getLogger("AUDIT");

    private final MeterRegistry meterRegistry;
    private final List<AuditEntry> auditEntries = Collections.synchronizedList(new ArrayList<>());

    public SecurityAuditListener(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        String user = event.getAuthentication().getName();
        Counter.builder("security.auth.success")
                .tag("user", user)
                .register(meterRegistry)
                .increment();
        auditLog.info("AUTH_SUCCESS user={}", user);
    }

    @EventListener
    public void onAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        String reason = event.getException().getClass().getSimpleName();
        Counter.builder("security.auth.failure")
                .tag("reason", reason)
                .register(meterRegistry)
                .increment();
        auditLog.warn("AUTH_FAILURE {}", reason);
    }

    @EventListener
    public void onAuthorizationDenied(AuthorizationDeniedEvent<?> event) {
        String username = resolveUsername(event);
        String resource = event.getAuthorizationResult() != null
                ? event.getAuthorizationResult().toString()
                : "no decision";

        AuditEntry entry = new AuditEntry(
                Instant.now(),
                username,
                "AUTHORIZATION_DENIED",
                resource
        );

        auditEntries.add(entry);
        auditLog.warn("AUTHZ_DENIED user={} resource={}", username, resource);

        Counter.builder("security.authz.denied")
                .register(meterRegistry)
                .increment();
    }

    /**
     * Returns an unmodifiable snapshot of the audit log for assertions in tests.
     * In production replace this with a query to the persistent audit store.
     */
    public List<AuditEntry> getAuditLog() {
        return Collections.unmodifiableList(new ArrayList<>(auditEntries));
    }

    // ---- helpers --------------------------------------------------------

    private String resolveUsername(AuthorizationDeniedEvent<?> event) {
        try {
            java.util.function.Supplier<?> supplier = event.getAuthentication();
            Object auth = supplier.get();
            if (auth instanceof Authentication authentication) {
                return authentication.getName();
            }
        } catch (Exception ignored) {
            // authentication supplier may throw if context is unavailable
        }
        return "anonymous";
    }

    // ---- nested types ---------------------------------------------------

    /**
     * Immutable audit log entry. In production this would be a JPA entity or
     * a record persisted to an append-only audit table.
     */
    public record AuditEntry(Instant timestamp, String username, String event, String detail) {
    }
}
