package com.cinetrack.security;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import java.util.function.Supplier;

/**
 * Custom {@link AuthorizationManager} that enforces subscription-tier access on
 * catalog endpoints.
 *
 * Rule: any path ending with {@code /premium} requires the caller to hold the
 * {@code TIER_PREMIUM} authority. All other paths only require authentication,
 * which the outer filter chain already ensures.
 *
 * By implementing {@code AuthorizationManager<RequestAuthorizationContext>} and
 * registering this bean in the security configuration, we keep subscription logic
 * out of SpEL strings and in a unit-testable class with a clear contract.
 *
 * Spring Security 7 changed the abstract method from {@code check} to
 * {@code authorize}, returning {@code AuthorizationResult} (a supertype of
 * {@code AuthorizationDecision}) to allow richer result objects.
 */
@Component
public class SubscriptionTierAuthorizationManager
        implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authenticationSupplier,
                                         RequestAuthorizationContext context) {
        String path = context.getRequest().getRequestURI();

        if (path.endsWith("/premium")) {
            Authentication auth = authenticationSupplier.get();
            boolean hasPremium = auth.getAuthorities().stream()
                    .anyMatch(a -> "TIER_PREMIUM".equals(a.getAuthority()));
            return new AuthorizationDecision(hasPremium);
        }

        // Non-premium paths: allow any authenticated user (authentication is
        // already required by the outer requestMatchers rule).
        return new AuthorizationDecision(true);
    }
}
