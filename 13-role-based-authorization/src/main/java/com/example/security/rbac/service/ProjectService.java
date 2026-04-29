package com.example.security.rbac.service;

import com.example.security.rbac.controller.ProjectController.CreateProjectRequest;
import com.example.security.rbac.controller.ProjectController.ProjectResponse;
import com.example.security.rbac.exception.ProjectNotFoundException;
import com.example.security.rbac.model.Project;
import com.example.security.rbac.repository.ProjectRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ProjectService {

    private final ProjectRepository projectRepository;

    public List<ProjectResponse> listProjects() {
        return projectRepository.findAll().stream()
                .map(p -> new ProjectResponse(p.getId(), p.getName(), p.getDescription(), p.getCreatedBy()))
                .toList();
    }

    public ProjectResponse createProject(CreateProjectRequest request, String createdBy) {
        var project = new Project(request.name(), request.description(), createdBy);
        var saved = projectRepository.save(project);
        return new ProjectResponse(saved.getId(), saved.getName(), saved.getDescription(), saved.getCreatedBy());
    }

    public void deleteProject(Long id) {
        if (!projectRepository.existsById(id)) {
            throw new ProjectNotFoundException(id);
        }
        projectRepository.deleteById(id);
    }
}
