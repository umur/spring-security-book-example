package com.example.security.testing.service;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Service layer carrying method-security annotations and all principal
 * inspection logic.
 *
 * Placing @PreAuthorize here (rather than on the controller) ensures the
 * rules are enforced for any caller — HTTP, scheduled jobs, or internal
 * service calls — and keeps security concerns out of the web layer.
 *
 * This is the primary target for {@code MethodSecurityTest}.
 */
@Service
public class ResourceService {

    /**
     * Public — no authentication required at the method level.
     * The security filter chain also permits /api/public unauthenticated.
     */
    public Map<String, String> getPublicInfo() {
        return Map.of(
                "message", "This endpoint is public",
                "status", "ok"
        );
    }

    /**
     * Requires any authenticated user (USER or ADMIN).
     * @PreAuthorize("isAuthenticated()") makes the contract explicit and
     * independently testable without going through the HTTP layer.
     *
     * Controller-facing overload: resolves the username from the Authentication
     * object so the controller never needs to inspect the principal itself.
     */
    @PreAuthorize("isAuthenticated()")
    public Map<String, Object> getUserResource(Authentication auth) {
        return getUserResource(extractUsername(auth));
    }

    /**
     * String-based overload retained for direct service-layer tests
     * (e.g. {@code MethodSecurityTest}) that populate the SecurityContext
     * manually and pass an explicit username.
     */
    @PreAuthorize("isAuthenticated()")
    public Map<String, Object> getUserResource(String username) {
        return Map.of(
                "message", "Hello, " + username,
                "role", "USER",
                "data", List.of("item1", "item2", "item3")
        );
    }

    /**
     * Requires ROLE_ADMIN.
     * Non-admin callers receive an AccessDeniedException which Spring
     * Security translates to HTTP 403.
     */
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> getAdminResource() {
        return Map.of(
                "message", "Admin resource",
                "users", List.of("user", "admin"),
                "systemInfo", Map.of("version", "1.0", "env", "test")
        );
    }

    /**
     * Accepts authenticated POSTs — CSRF protection is tested against this
     * endpoint via MockMvc .with(csrf()) / without csrf.
     *
     * Controller-facing overload: resolves the owner from the Authentication
     * object so the controller never needs to inspect the principal itself.
     */
    @PreAuthorize("isAuthenticated()")
    public Map<String, String> createData(String content, Authentication auth) {
        return createData(content, extractUsername(auth));
    }

    /**
     * String-based overload retained for direct service-layer tests.
     */
    @PreAuthorize("isAuthenticated()")
    public Map<String, String> createData(String content, String owner) {
        return Map.of(
                "id", java.util.UUID.randomUUID().toString(),
                "content", content,
                "owner", owner,
                "status", "created"
        );
    }

    /**
     * Resolves a display name from any principal type Spring Security may
     * inject. All instanceof checks and fallback logic live here — the web
     * layer never needs to touch the principal directly.
     */
    public String extractUsername(Authentication auth) {
        if (auth == null) {
            return "anonymous";
        }
        Object principal = auth.getPrincipal();
        if (principal instanceof UserDetails ud) {
            return ud.getUsername();
        }
        if (principal instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        if (principal != null) {
            return principal.toString();
        }
        return "anonymous";
    }
}
