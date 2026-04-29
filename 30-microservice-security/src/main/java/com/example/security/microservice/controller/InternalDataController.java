package com.example.security.microservice.controller;

import com.example.security.microservice.dto.InternalDataResponse;
import com.example.security.microservice.service.DataService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Resource server endpoint — validates incoming JWT and serves internal data.
 */
@RestController
@RequestMapping("/api/internal")
@RequiredArgsConstructor
public class InternalDataController {

    private final DataService dataService;

    @GetMapping("/data")
    ResponseEntity<InternalDataResponse> getData(Authentication authentication) {
        return ResponseEntity.ok(dataService.getInternalData(authentication));
    }
}
