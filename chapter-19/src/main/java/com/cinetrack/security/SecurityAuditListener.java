package com.cinetrack.security;

import org.springframework.context.event.EventListener;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Listens for {@link AuthorizationDeniedEvent} published by the Spring Security
 * authorization infrastructure and records each denial in memory.
 *
 * Spring Security 6+ publishes {@code AuthorizationDeniedEvent} whenever an
 * authorization decision results in access being denied — whether at the HTTP
 * filter layer or at a {@code @PreAuthorize} / {@code @PostAuthorize} method.
 *
 * The event carries the {@code Authentication} as a {@code Supplier} that is
 * only valid on the publishing thread. This listener therefore resolves the
 * principal name eagerly inside the event handler — while the request thread
 * and its {@code SecurityContext} are still active — and stores the name
 * separately. Callers that need the raw event for result-code inspection can
 * use {@link #getDenials()}; callers that need the principal name use
 * {@link #getDeniedPrincipalNames()}.
 *
 * In production you would write denials to an audit log, Kafka topic, or
 * metrics counter rather than holding them in memory.
 */
@Component
public class SecurityAuditListener {

    private final List<AuthorizationDeniedEvent<?>> denials =
            Collections.synchronizedList(new ArrayList<>());

    private final List<String> deniedPrincipalNames =
            Collections.synchronizedList(new ArrayList<>());

    @EventListener(AuthorizationDeniedEvent.class)
    public void onAuthorizationDenied(AuthorizationDeniedEvent<?> event) {
        denials.add(event);

        // Resolve the principal name eagerly: the Supplier is only callable on
        // the publishing thread. Storing the name lets tests assert on it after
        // the request has completed without re-entering the SecurityContext.
        try {
            Authentication auth = event.getAuthentication().get();
            if (auth != null) {
                deniedPrincipalNames.add(auth.getName());
            }
        } catch (Exception ignored) {
            // If the supplier cannot be resolved (anonymous request), skip.
        }
    }

    /**
     * Returns a snapshot of all recorded denial events since application start
     * (or since the last {@link #clear()} call).
     */
    public List<AuthorizationDeniedEvent<?>> getDenials() {
        return List.copyOf(denials);
    }

    /**
     * Returns the principal names of all denied requests, resolved eagerly at
     * event-publication time. Safe to call from any thread after the request.
     */
    public List<String> getDeniedPrincipalNames() {
        return List.copyOf(deniedPrincipalNames);
    }

    /** Clears all recorded denials — useful for test setup. */
    public void clear() {
        denials.clear();
        deniedPrincipalNames.clear();
    }
}
