package com.example.security.ratelimit.service;

import java.time.Instant;

public record AccountStatusResponse(
        String username,
        boolean locked,
        int failureCount,
        Instant lockExpiresAt
) {}
