package com.cinetrack.admin;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Admin-only endpoint. Requires {@code ROLE_ADMINS} — enforced by the SecurityFilterChain.
 * Only users in LDAP group {@code cn=admins} can reach this endpoint.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping("/users")
    public List<String> users() {
        return List.of("alice", "bob");
    }
}
