package com.example.security.custompermission.service;

import com.example.security.custompermission.controller.ProjectController.AddMemberRequest;
import com.example.security.custompermission.controller.ProjectController.CreateProjectRequest;
import com.example.security.custompermission.controller.ProjectController.MemberResponse;
import com.example.security.custompermission.controller.ProjectController.ProjectResponse;
import com.example.security.custompermission.controller.ProjectController.UpdateProjectRequest;
import com.example.security.custompermission.model.Project;
import com.example.security.custompermission.model.ProjectMember;
import com.example.security.custompermission.model.ProjectRole;
import com.example.security.custompermission.repository.ProjectMemberRepository;
import com.example.security.custompermission.repository.ProjectRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * All business logic and security annotations live here.
 *
 * hasPermission() delegates to {@link com.example.security.custompermission.security.ProjectPermissionEvaluator}.
 *
 * Permission strings:
 *   VIEW           — VIEWER, EDITOR, OWNER
 *   EDIT           — EDITOR, OWNER
 *   DELETE         — OWNER only
 *   MANAGE_MEMBERS — OWNER only
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class ProjectService {

    private final ProjectRepository projectRepository;
    private final ProjectMemberRepository memberRepository;

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    public List<Project> findAll() {
        return projectRepository.findAll();
    }

    /**
     * Returns the project if the caller has VIEW permission.
     * Uses the id-based form: hasPermission(targetId, targetType, permission).
     */
    @PostAuthorize("hasPermission(returnObject.id, 'com.example.security.custompermission.model.Project', 'VIEW')")
    public Project findById(Long id) {
        return projectRepository.findById(id)
                .orElseThrow(() -> new ProjectNotFoundException(id));
    }

    // -----------------------------------------------------------------------
    // Mutations
    // -----------------------------------------------------------------------

    /**
     * Creates a project and registers the creator as OWNER.
     */
    @Transactional
    public Project create(String name, String description, String ownerUsername) {
        Project project = projectRepository.save(new Project(name, description));
        memberRepository.save(new ProjectMember(project, ownerUsername, ProjectRole.OWNER));
        return project;
    }

    /**
     * Updates name and description. Caller must have EDIT permission.
     */
    @PreAuthorize("hasPermission(#id, 'com.example.security.custompermission.model.Project', 'EDIT')")
    @Transactional
    public Project update(Long id, String name, String description) {
        Project project = projectRepository.findById(id)
                .orElseThrow(() -> new ProjectNotFoundException(id));
        project.setName(name);
        project.setDescription(description);
        return projectRepository.save(project);
    }

    /**
     * Deletes the project. Caller must have DELETE permission (OWNER only).
     */
    @PreAuthorize("hasPermission(#id, 'com.example.security.custompermission.model.Project', 'DELETE')")
    @Transactional
    public void delete(Long id) {
        if (!projectRepository.existsById(id)) {
            throw new ProjectNotFoundException(id);
        }
        projectRepository.deleteById(id);
    }

    /**
     * Adds a team member with the given role.
     * Caller must have MANAGE_MEMBERS permission (OWNER only).
     */
    @PreAuthorize("hasPermission(#projectId, 'com.example.security.custompermission.model.Project', 'MANAGE_MEMBERS')")
    @Transactional
    public ProjectMember addMember(Long projectId, String username, ProjectRole role) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new ProjectNotFoundException(projectId));
        // Upsert: update role if member already exists
        return memberRepository.findByProjectIdAndUsername(projectId, username)
                .map(existing -> {
                    existing.setRole(role);
                    return memberRepository.save(existing);
                })
                .orElseGet(() -> memberRepository.save(new ProjectMember(project, username, role)));
    }

    // -----------------------------------------------------------------------
    // DTO-returning façade methods (used by the thin controller)
    // -----------------------------------------------------------------------

    public List<ProjectResponse> listProjects() {
        return findAll().stream()
                .map(p -> new ProjectResponse(p.getId(), p.getName(), p.getDescription()))
                .toList();
    }

    @PostAuthorize("hasPermission(returnObject.id, 'com.example.security.custompermission.model.Project', 'VIEW')")
    public ProjectResponse getProjectResponse(Long id) {
        Project p = projectRepository.findById(id)
                .orElseThrow(() -> new ProjectNotFoundException(id));
        return new ProjectResponse(p.getId(), p.getName(), p.getDescription());
    }

    @Transactional
    public ProjectResponse createProject(CreateProjectRequest request, String ownerUsername) {
        Project project = projectRepository.save(new Project(request.name(), request.description()));
        memberRepository.save(new ProjectMember(project, ownerUsername, ProjectRole.OWNER));
        return new ProjectResponse(project.getId(), project.getName(), project.getDescription());
    }

    @PreAuthorize("hasPermission(#id, 'com.example.security.custompermission.model.Project', 'EDIT')")
    @Transactional
    public ProjectResponse updateProject(Long id, UpdateProjectRequest request) {
        Project project = projectRepository.findById(id)
                .orElseThrow(() -> new ProjectNotFoundException(id));
        project.setName(request.name());
        project.setDescription(request.description());
        project = projectRepository.save(project);
        return new ProjectResponse(project.getId(), project.getName(), project.getDescription());
    }

    @PreAuthorize("hasPermission(#projectId, 'com.example.security.custompermission.model.Project', 'MANAGE_MEMBERS')")
    @Transactional
    public MemberResponse addMemberFromRequest(Long projectId, AddMemberRequest request) {
        ProjectRole role = ProjectRole.valueOf(request.role().toUpperCase());
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new ProjectNotFoundException(projectId));
        ProjectMember m = memberRepository.findByProjectIdAndUsername(projectId, request.username())
                .map(existing -> {
                    existing.setRole(role);
                    return memberRepository.save(existing);
                })
                .orElseGet(() -> memberRepository.save(new ProjectMember(project, request.username(), role)));
        return new MemberResponse(m.getId(), m.getUsername(), m.getRole().name());
    }

    // -----------------------------------------------------------------------
    // Exception
    // -----------------------------------------------------------------------

    public static class ProjectNotFoundException extends RuntimeException {
        public ProjectNotFoundException(Long id) {
            super("Project not found: " + id);
        }
    }
}
