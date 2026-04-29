package com.example.security.session.dto;

import java.util.List;

public record SessionInfoResponse(
        String username,
        String sessionId,
        String creationTime,
        String lastAccessedTime,
        int maxInactiveInterval,
        List<String> roles
) {}
