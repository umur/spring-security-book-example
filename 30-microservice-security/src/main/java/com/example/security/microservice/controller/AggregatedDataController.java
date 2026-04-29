package com.example.security.microservice.controller;

import com.example.security.microservice.dto.AggregatedResponse;
import com.example.security.microservice.service.DataService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint that acts as an OAuth2 client — obtains a token via client_credentials
 * and calls an external service, then aggregates the result with local data.
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AggregatedDataController {

    private final DataService dataService;

    @GetMapping("/aggregated")
    ResponseEntity<AggregatedResponse> getAggregated() {
        return ResponseEntity.ok(dataService.getAggregatedData());
    }
}
