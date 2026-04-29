package com.example.security.multitenancy.controller;

import com.example.security.multitenancy.model.TenantData;
import com.example.security.multitenancy.service.DataService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/data")
@RequiredArgsConstructor
public class DataController {

    private final DataService dataService;

    public record CreateDataRequest(String content) {}
    public record DataResponse(Long id, String tenantId, String content) {}

    @GetMapping
    public ResponseEntity<List<DataResponse>> getData() {
        List<DataResponse> result = dataService.findAllForCurrentTenant().stream()
                .map(d -> new DataResponse(d.getId(), d.getTenantId(), d.getContent()))
                .toList();
        return ResponseEntity.ok(result);
    }

    @PostMapping
    public ResponseEntity<DataResponse> createData(@RequestBody CreateDataRequest request) {
        TenantData saved = dataService.createForCurrentTenant(request.content());
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(new DataResponse(saved.getId(), saved.getTenantId(), saved.getContent()));
    }
}
