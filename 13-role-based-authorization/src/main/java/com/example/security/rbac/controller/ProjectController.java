package com.example.security.rbac.controller;

import com.example.security.rbac.service.ProjectService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class ProjectController {

    private final ProjectService projectService;

    // Public info endpoint — no auth required
    @GetMapping("/api/public/info")
    public InfoResponse publicInfo() {
        return new InfoResponse("Role-Based Authorization Example", "1.0");
    }

    // USER and above can list projects
    @GetMapping("/api/projects")
    @PreAuthorize("hasRole('USER')")
    public List<ProjectResponse> listProjects() {
        return projectService.listProjects();
    }

    // MANAGER and above can create projects
    @PostMapping("/api/projects")
    @PreAuthorize("hasRole('MANAGER')")
    public ResponseEntity<ProjectResponse> createProject(@RequestBody CreateProjectRequest request,
                                                         @AuthenticationPrincipal UserDetails principal) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(projectService.createProject(request, principal.getUsername()));
    }

    // ADMIN only can delete projects
    @DeleteMapping("/api/projects/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteProject(@PathVariable Long id) {
        projectService.deleteProject(id);
        return ResponseEntity.noContent().build();
    }

    // --- DTOs as records ---

    public record InfoResponse(String name, String version) {}

    public record ProjectResponse(Long id, String name, String description, String createdBy) {}

    public record CreateProjectRequest(String name, String description) {}
}
