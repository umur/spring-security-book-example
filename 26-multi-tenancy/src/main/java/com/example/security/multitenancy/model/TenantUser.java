package com.example.security.multitenancy.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * A user that belongs to a specific tenant.
 * The same username may exist in multiple tenants — uniqueness is enforced
 * by the (tenantId, username) composite unique constraint.
 */
@Entity
@Table(name = "tenant_users",
        uniqueConstraints = @UniqueConstraint(columnNames = {"tenant_id", "username"}))
@Getter
@Setter
@NoArgsConstructor
public class TenantUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String role;

    @Column(nullable = false)
    private boolean enabled = true;

    public TenantUser(String tenantId, String username, String password, String role) {
        this.tenantId = tenantId;
        this.username = username;
        this.password = password;
        this.role = role;
    }
}
