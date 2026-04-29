package com.example.security.rbac.repository;

import com.example.security.rbac.model.Project;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProjectRepository extends JpaRepository<Project, Long> {
}
