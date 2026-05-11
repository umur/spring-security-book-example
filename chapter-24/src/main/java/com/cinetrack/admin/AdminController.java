package com.cinetrack.admin;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Admin-only endpoint. A {@code ROLE_USER} attempting to reach this path
 * triggers an {@link org.springframework.security.authorization.event.AuthorizationDeniedEvent}
 * which {@link com.cinetrack.security.SecurityAuditListener} writes to the
 * audit log and counts in the {@code authz.denials} Micrometer counter.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping("/users")
    public List<UserSummary> listUsers() {
        return List.of(
                new UserSummary("alice", "BASIC"),
                new UserSummary("charlie", "PREMIUM")
        );
    }
}
