package com.example.security.custompermission.model;

/**
 * Roles a team member can hold within a project.
 *
 * Permission hierarchy:
 *   OWNER  — can VIEW, EDIT, DELETE the project and manage members
 *   EDITOR — can VIEW and EDIT the project
 *   VIEWER — can only VIEW the project
 */
public enum ProjectRole {
    VIEWER,
    EDITOR,
    OWNER
}
