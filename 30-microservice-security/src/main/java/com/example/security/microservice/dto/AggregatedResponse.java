package com.example.security.microservice.dto;

import java.time.Instant;
import java.util.List;

public record AggregatedResponse(
        String aggregatorServiceId,
        List<String> localRecords,
        ExternalData externalData,
        Instant aggregatedAt
) {
    public record ExternalData(
            String sourceService,
            List<String> items
    ) {}
}
