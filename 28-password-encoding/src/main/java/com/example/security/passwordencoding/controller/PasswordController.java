package com.example.security.passwordencoding.controller;

import com.example.security.passwordencoding.dto.EncodeResponse;
import com.example.security.passwordencoding.dto.PasswordInfoResponse;
import com.example.security.passwordencoding.dto.VerifyRequest;
import com.example.security.passwordencoding.dto.VerifyResponse;
import com.example.security.passwordencoding.service.PasswordService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST API demonstrating different password encoding strategies.
 *
 * <p>All endpoints require HTTP Basic authentication (see SecurityConfig).
 * All encoding, verification, and info logic is delegated to {@link PasswordService}.</p>
 */
@RestController
@RequestMapping("/api/passwords")
@RequiredArgsConstructor
public class PasswordController {

    private final PasswordService passwordService;

    @GetMapping("/encode")
    public ResponseEntity<EncodeResponse> encode(
            @RequestParam String raw,
            @RequestParam(defaultValue = "bcrypt") String algorithm) {
        return ResponseEntity.ok(passwordService.encode(raw, algorithm));
    }

    @PostMapping("/verify")
    public ResponseEntity<VerifyResponse> verify(@RequestBody VerifyRequest request) {
        return ResponseEntity.ok(passwordService.verify(request));
    }

    @GetMapping("/info")
    public ResponseEntity<PasswordInfoResponse> info() {
        return ResponseEntity.ok(passwordService.info());
    }
}
