package com.example.security.microservice.service;

import com.example.security.microservice.dto.AggregatedResponse;
import com.example.security.microservice.dto.InternalDataResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

/**
 * Handles all business logic for data retrieval and aggregation.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DataService {

    private static final String SERVICE_ID = "microservice-security-example";

    private final ExternalServiceClient externalServiceClient;

    /**
     * Returns internal data for a validated service token request.
     * The caller's identity (subject claim) is extracted from the JWT authentication.
     */
    public InternalDataResponse getInternalData(Authentication authentication) {
        String callerSubject = authentication.getName();
        log.debug("Serving internal data to caller: {}", callerSubject);

        return new InternalDataResponse(
                SERVICE_ID,
                "ok",
                List.of("record-001", "record-002", "record-003"),
                Instant.now()
        );
    }

    /**
     * Aggregates local data with data fetched from the external service using
     * the client_credentials flow. The external call is performed by
     * {@link ExternalServiceClient} which manages token acquisition and caching.
     */
    public AggregatedResponse getAggregatedData() {
        log.debug("Aggregating local data with external service data");

        List<String> localRecords = List.of("local-001", "local-002");
        AggregatedResponse.ExternalData externalData = externalServiceClient.fetchExternalData();

        return new AggregatedResponse(
                SERVICE_ID,
                localRecords,
                externalData,
                Instant.now()
        );
    }
}
