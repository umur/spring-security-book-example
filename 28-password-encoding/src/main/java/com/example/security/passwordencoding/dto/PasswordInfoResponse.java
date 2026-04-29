package com.example.security.passwordencoding.dto;

import java.util.List;
import java.util.Map;

public record PasswordInfoResponse(
        String description,
        String currentDefault,
        Map<String, String> supportedAlgorithms,
        List<String> migrationSteps,
        String exampleBcryptHash,
        String exampleDelegatingHash,
        boolean delegatingCanVerifyBcryptPrefixedHash
) {}
