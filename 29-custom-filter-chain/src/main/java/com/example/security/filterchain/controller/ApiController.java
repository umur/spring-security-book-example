package com.example.security.filterchain.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class ApiController {

    /** Public endpoint — no authentication required (Chain 2). */
    @GetMapping("/api/public/info")
    ResponseEntity<Map<String, String>> publicInfo() {
        return ResponseEntity.ok(Map.of(
                "status", "ok",
                "message", "This endpoint is publicly accessible"
        ));
    }

    /** Protected endpoint — requires USER role (Chain 3). */
    @GetMapping("/api/data")
    ResponseEntity<Map<String, Object>> userData(
            @AuthenticationPrincipal UserDetails user) {
        return ResponseEntity.ok(Map.of(
                "resource", "user-data",
                "owner", user.getUsername(),
                "items", java.util.List.of("item-1", "item-2", "item-3")
        ));
    }

    /** Admin endpoint — requires ADMIN role (Chain 1). */
    @GetMapping("/api/admin/settings")
    ResponseEntity<Map<String, Object>> adminSettings(
            @AuthenticationPrincipal UserDetails user) {
        return ResponseEntity.ok(Map.of(
                "resource", "admin-settings",
                "managedBy", user.getUsername(),
                "maxSessions", 1,
                "rateLimitEnabled", true
        ));
    }

    /** Admin endpoint — requires ADMIN role (Chain 1). */
    @GetMapping("/api/admin/audit")
    ResponseEntity<Map<String, Object>> adminAudit(
            @AuthenticationPrincipal UserDetails user) {
        return ResponseEntity.ok(Map.of(
                "resource", "audit-log",
                "requestedBy", user.getUsername(),
                "entries", java.util.List.of(
                        "2026-03-26T10:00:00Z - admin logged in",
                        "2026-03-26T10:05:00Z - settings viewed"
                )
        ));
    }
}
