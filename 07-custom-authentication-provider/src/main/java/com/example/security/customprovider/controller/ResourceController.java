package com.example.security.customprovider.controller;

import com.example.security.customprovider.service.ResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/resources")
@RequiredArgsConstructor
public class ResourceController {

    private final ResourceService resourceService;

    public record ResourceResponse(Long id, String name, String description) {}

    @GetMapping
    public ResponseEntity<List<ResourceResponse>> listResources() {
        return ResponseEntity.ok(resourceService.listResources());
    }

    @GetMapping("/admin")
    public ResponseEntity<Map<String, Object>> adminResource(Principal principal) {
        return ResponseEntity.ok(resourceService.getAdminResource(principal.getName()));
    }
}
