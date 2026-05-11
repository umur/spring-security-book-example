package com.cinetrack.crypto;

import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Demo endpoint that shows BCrypt encoding in action.
 *
 * This endpoint is intentionally simple: it accepts a plaintext password and
 * returns the BCrypt hash. In a real application you would never expose a
 * hashing endpoint like this; the purpose here is to give readers a live
 * demonstration of what a BCrypt hash looks like and how the cost factor
 * affects latency.
 *
 * The endpoint is protected by HTTP Basic (configured in SecurityConfig).
 */
@RestController
@RequestMapping("/api/crypto")
public class CryptoController {

    private final BCryptPasswordEncoder encoder;

    public CryptoController(BCryptPasswordEncoder encoder) {
        this.encoder = encoder;
    }

    /**
     * Hashes the submitted plaintext password and returns the encoded form.
     *
     * Request body: {@code {"password": "my-secret"}}
     * Response:     {@code {"encoded": "$2a$12$..."}}
     */
    @PostMapping("/hash")
    public ResponseEntity<Map<String, String>> hash(@RequestBody Map<String, String> body) {
        String plaintext = body.get("password");
        if (plaintext == null || plaintext.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "password must not be blank"));
        }
        String encoded = encoder.encode(plaintext);
        return ResponseEntity.ok(Map.of("encoded", encoded));
    }
}
