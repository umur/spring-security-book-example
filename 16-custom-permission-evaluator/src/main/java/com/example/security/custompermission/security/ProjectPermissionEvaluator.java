package com.example.security.custompermission.security;

import com.example.security.custompermission.model.Project;
import com.example.security.custompermission.model.ProjectRole;
import com.example.security.custompermission.repository.ProjectMemberRepository;
import com.example.security.custompermission.repository.ProjectRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;

/**
 * Custom {@link PermissionEvaluator} that derives permissions from team membership
 * stored in the database — no ACL tables needed.
 *
 * Supported permission strings:
 *   VIEW  — granted to VIEWER, EDITOR, OWNER
 *   EDIT  — granted to EDITOR, OWNER
 *   DELETE / MANAGE_MEMBERS — granted to OWNER only
 *
 * Both forms of {@code hasPermission()} are supported:
 *   hasPermission(object, permission)            — object is a Project instance
 *   hasPermission(targetId, targetType, permission) — targetId is a Long project ID
 */
@Component
@RequiredArgsConstructor
public class ProjectPermissionEvaluator implements PermissionEvaluator {

    private final ProjectMemberRepository memberRepository;
    private final ProjectRepository projectRepository;

    // -----------------------------------------------------------------------
    // hasPermission(Authentication, Object domainObject, Object permission)
    // -----------------------------------------------------------------------

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || targetDomainObject == null || permission == null) {
            return false;
        }
        if (!(targetDomainObject instanceof Project project)) {
            return false;
        }
        return evaluate(authentication.getName(), project.getId(), permission.toString());
    }

    // -----------------------------------------------------------------------
    // hasPermission(Authentication, Serializable targetId, String targetType, Object permission)
    // -----------------------------------------------------------------------

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId,
                                  String targetType, Object permission) {
        if (authentication == null || targetId == null || permission == null) {
            return false;
        }
        if (!"com.example.security.custompermission.model.Project".equals(targetType)
                && !"Project".equals(targetType)) {
            return false;
        }
        Long projectId = toLong(targetId);
        if (projectId == null) return false;
        return evaluate(authentication.getName(), projectId, permission.toString());
    }

    // -----------------------------------------------------------------------
    // Core logic
    // -----------------------------------------------------------------------

    private boolean evaluate(String username, Long projectId, String permission) {
        return memberRepository.findByProjectIdAndUsername(projectId, username)
                .map(member -> switch (permission.toUpperCase()) {
                    case "VIEW"           -> true; // all roles can VIEW
                    case "EDIT"           -> member.getRole() == ProjectRole.EDITOR
                                            || member.getRole() == ProjectRole.OWNER;
                    case "DELETE",
                         "MANAGE_MEMBERS" -> member.getRole() == ProjectRole.OWNER;
                    default -> false;
                })
                .orElse(false);
    }

    private Long toLong(Serializable id) {
        if (id instanceof Long l) return l;
        if (id instanceof Integer i) return i.longValue();
        try {
            return Long.parseLong(id.toString());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
