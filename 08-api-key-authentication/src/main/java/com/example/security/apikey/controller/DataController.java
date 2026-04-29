package com.example.security.apikey.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/data")
public class DataController {

    @GetMapping
    public ResponseEntity<Map<String, Object>> getData(@AuthenticationPrincipal String owner) {
        return ResponseEntity.ok(Map.of(
                "message", "Data accessible with valid API key",
                "owner", owner != null ? owner : "unknown"
        ));
    }

    @GetMapping("/admin")
    public ResponseEntity<Map<String, Object>> getAdminData(@AuthenticationPrincipal String owner) {
        return ResponseEntity.ok(Map.of(
                "message", "Admin data accessible with ADMIN scope",
                "owner", owner != null ? owner : "unknown"
        ));
    }
}
