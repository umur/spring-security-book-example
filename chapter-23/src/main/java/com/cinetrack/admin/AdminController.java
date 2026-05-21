package com.cinetrack.admin;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Administrative endpoint restricted to {@code ROLE_ADMIN}.
 *
 * The access rule is declared in {@link com.cinetrack.security.SecurityConfig}
 * at the URL level. Tests for this endpoint demonstrate that
 * {@code @WithMockUser(roles = "ADMIN")} grants access while
 * {@code @WithMockUser(roles = "USER")} is rejected with a 403.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping("/users")
    public List<UserSummary> listUsers() {
        return List.of(
                new UserSummary("alice", "BASIC"),
                new UserSummary("charlie", "PREMIUM"),
                new UserSummary("diana", "PREMIUM")
        );
    }
}
