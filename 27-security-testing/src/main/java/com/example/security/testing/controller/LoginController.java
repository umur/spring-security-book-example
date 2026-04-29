package com.example.security.testing.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Minimal login endpoint — returns a JSON hint so that TestRestTemplate
 * integration tests receive a 200 OK (after following the redirect from a
 * protected resource) rather than a 404.
 *
 * This module is a REST-only testing reference; there is no Thymeleaf UI.
 */
@RestController
public class LoginController {

    @GetMapping("/login")
    public ResponseEntity<Map<String, String>> loginPage() {
        return ResponseEntity.ok(Map.of(
                "message", "Authentication required",
                "hint", "Use HTTP Basic, form-login, or a Bearer JWT token"
        ));
    }
}
