package com.example.security.custompermission.repository;

import com.example.security.custompermission.model.Project;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProjectRepository extends JpaRepository<Project, Long> {
}
