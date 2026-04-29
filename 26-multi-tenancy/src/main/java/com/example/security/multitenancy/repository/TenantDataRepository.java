package com.example.security.multitenancy.repository;

import com.example.security.multitenancy.model.TenantData;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TenantDataRepository extends JpaRepository<TenantData, Long> {

    List<TenantData> findAllByTenantId(String tenantId);
}
