package com.example.security.cors.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    /**
     * GET /api/public
     * Open to any origin — CORS policy allows wildcard origin.
     */
    @GetMapping("/public")
    public ResponseEntity<Map<String, String>> publicEndpoint() {
        return ResponseEntity.ok(Map.of(
                "endpoint", "public",
                "message", "This endpoint allows cross-origin requests from any origin"
        ));
    }

    /**
     * GET /api/data
     * Restricted CORS — only configured trusted origins receive CORS headers.
     */
    @GetMapping("/data")
    public ResponseEntity<Map<String, String>> getData() {
        return ResponseEntity.ok(Map.of(
                "endpoint", "data",
                "message", "This endpoint restricts CORS to specific trusted origins"
        ));
    }

    /**
     * POST /api/data
     * Restricted CORS with specific allowed request headers.
     */
    @PostMapping("/data")
    public ResponseEntity<Map<String, String>> postData(@RequestBody(required = false) Map<String, Object> body) {
        return ResponseEntity.ok(Map.of(
                "endpoint", "data",
                "method", "POST",
                "message", "Data accepted from trusted origin"
        ));
    }
}
