package com.example.security.custompermission.repository;

import com.example.security.custompermission.model.ProjectMember;
import com.example.security.custompermission.model.ProjectRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ProjectMemberRepository extends JpaRepository<ProjectMember, Long> {
    Optional<ProjectMember> findByProjectIdAndUsername(Long projectId, String username);
    boolean existsByProjectIdAndUsernameAndRole(Long projectId, String username, ProjectRole role);
}
