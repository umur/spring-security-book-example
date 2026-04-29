package com.example.security.customprovider.controller;

import com.example.security.customprovider.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Issues domain tokens to already-authenticated users (DB auth via HTTP Basic).
 * The generated token can then be used in the {@code X-Domain-Token} header for
 * subsequent requests, demonstrating the two-provider chain in action.
 */
@RestController
@RequestMapping("/api/tokens")
@RequiredArgsConstructor
public class TokenController {

    private final TokenService tokenService;

    public record TokenResponse(String token, String username, String expiresAt) {}

    @PostMapping
    public ResponseEntity<TokenResponse> generateToken(@AuthenticationPrincipal UserDetails principal) {
        return ResponseEntity.status(HttpStatus.CREATED).body(tokenService.generateToken(principal));
    }
}
