package com.cinetrack.admin;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Administration endpoint. Restricted to ROLE_ADMIN — enforced in SecurityConfig.
 *
 * Returning the user list here is intentionally simplified. In production,
 * this would delegate to a UserService backed by a real data store.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping("/users")
    public List<UserSummary> listUsers() {
        return List.of(
                new UserSummary("alice", "VIEWER"),
                new UserSummary("bob", "VIEWER"),
                new UserSummary("admin", "ADMIN")
        );
    }
}
