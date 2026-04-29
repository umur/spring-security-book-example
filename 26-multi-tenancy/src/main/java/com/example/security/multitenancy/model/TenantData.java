package com.example.security.multitenancy.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Application data that is scoped to a specific tenant.
 * All queries must filter by {@code tenantId} to enforce isolation.
 */
@Entity
@Table(name = "tenant_data")
@Getter
@Setter
@NoArgsConstructor
public class TenantData {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(nullable = false)
    private String content;

    public TenantData(String tenantId, String content) {
        this.tenantId = tenantId;
        this.content = content;
    }
}
