package com.example.security.testing.controller;

import com.example.security.testing.service.ResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Thin REST controller — all business and security logic lives in
 * {@link ResourceService}. The controller's only job is HTTP mapping and
 * delegating to the service.
 *
 * Endpoints:
 *   GET  /api/public  — no auth required
 *   GET  /api/user    — requires any authenticated user
 *   GET  /api/admin   — requires ROLE_ADMIN
 *   POST /api/data    — requires auth + CSRF token
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class ResourceController {

    private final ResourceService resourceService;

    @GetMapping("/public")
    public ResponseEntity<Map<String, String>> getPublic() {
        return ResponseEntity.ok(resourceService.getPublicInfo());
    }

    @GetMapping("/user")
    public ResponseEntity<Map<String, Object>> getUser(Authentication auth) {
        return ResponseEntity.ok(resourceService.getUserResource(auth));
    }

    @GetMapping("/admin")
    public ResponseEntity<Map<String, Object>> getAdmin() {
        return ResponseEntity.ok(resourceService.getAdminResource());
    }

    @PostMapping("/data")
    public ResponseEntity<Map<String, String>> postData(
            @RequestBody DataRequest request, Authentication auth) {
        return ResponseEntity.status(201)
                .body(resourceService.createData(request.content(), auth));
    }

    // --- DTO ---

    public record DataRequest(String content) {}
}
