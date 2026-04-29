package com.example.security.headers.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    /**
     * GET /api/info
     * Returns basic application info. All configured security headers are present
     * in the response automatically via the SecurityFilterChain header configuration.
     */
    @GetMapping("/info")
    public ResponseEntity<Map<String, String>> info() {
        return ResponseEntity.ok(Map.of(
                "application", "security-headers-example",
                "status", "running",
                "message", "All HTTP security headers are set on every response"
        ));
    }

    /**
     * GET /api/headers
     * Returns a description of each security header configured and its purpose.
     */
    @GetMapping("/headers")
    public ResponseEntity<Map<String, String>> headersDescription() {
        Map<String, String> descriptions = new LinkedHashMap<>();
        descriptions.put("X-Content-Type-Options",
                "nosniff — prevents MIME-type sniffing; browser must honour declared Content-Type");
        descriptions.put("X-Frame-Options",
                "DENY — prevents the page from being embedded in any iframe (clickjacking protection)");
        descriptions.put("Strict-Transport-Security",
                "max-age=31536000; includeSubDomains; preload — forces HTTPS for one year across all subdomains");
        descriptions.put("Content-Security-Policy",
                "default-src 'self' — restricts resource loading to same origin; frame-ancestors 'none' blocks embedding");
        descriptions.put("Referrer-Policy",
                "strict-origin-when-cross-origin — sends full URL for same-origin, only origin for cross-origin HTTPS");
        descriptions.put("Permissions-Policy",
                "camera=(), microphone=(), geolocation=(), payment=() — disables sensitive browser features");
        descriptions.put("Cache-Control",
                "no-cache, no-store, max-age=0, must-revalidate — prevents caching of sensitive responses");
        return ResponseEntity.ok(descriptions);
    }
}
