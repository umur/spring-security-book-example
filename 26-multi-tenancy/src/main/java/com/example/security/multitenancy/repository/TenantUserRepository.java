package com.example.security.multitenancy.repository;

import com.example.security.multitenancy.model.TenantUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TenantUserRepository extends JpaRepository<TenantUser, Long> {

    Optional<TenantUser> findByTenantIdAndUsername(String tenantId, String username);
}
