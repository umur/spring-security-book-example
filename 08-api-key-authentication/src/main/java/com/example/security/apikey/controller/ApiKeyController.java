package com.example.security.apikey.controller;

import com.example.security.apikey.service.ApiKeyService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@RestController
@RequestMapping("/api/keys")
@RequiredArgsConstructor
public class ApiKeyController {

    private final ApiKeyService apiKeyService;

    public record GenerateKeyRequest(String owner, String roles) {}

    public record GenerateKeyResponse(String apiKey, Long id, String owner, String roles, Instant createdAt) {}

    @PostMapping
    public ResponseEntity<GenerateKeyResponse> generateKey(@RequestBody GenerateKeyRequest request) {
        ApiKeyService.GeneratedApiKey result = apiKeyService.generate(request.owner(), request.roles());
        GenerateKeyResponse response = new GenerateKeyResponse(
                result.rawKey(),
                result.savedEntity().getId(),
                result.savedEntity().getOwner(),
                result.savedEntity().getRoles(),
                result.savedEntity().getCreatedAt()
        );
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
