package com.example.security.microservice.dto;

import java.time.Instant;
import java.util.List;

public record InternalDataResponse(
        String serviceId,
        String status,
        List<String> records,
        Instant retrievedAt
) {}
