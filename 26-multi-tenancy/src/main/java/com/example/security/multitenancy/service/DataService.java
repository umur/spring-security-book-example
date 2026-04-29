package com.example.security.multitenancy.service;

import com.example.security.multitenancy.model.TenantData;
import com.example.security.multitenancy.repository.TenantDataRepository;
import com.example.security.multitenancy.security.TenantContext;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Handles CRUD for {@link TenantData}, always scoping queries to the tenant
 * that is set in {@link TenantContext} for the current request thread.
 */
@Service
@RequiredArgsConstructor
public class DataService {

    private final TenantDataRepository tenantDataRepository;

    @Transactional(readOnly = true)
    public List<TenantData> findAllForCurrentTenant() {
        String tenantId = TenantContext.getTenantId();
        return tenantDataRepository.findAllByTenantId(tenantId);
    }

    @Transactional
    public TenantData createForCurrentTenant(String content) {
        String tenantId = TenantContext.getTenantId();
        return tenantDataRepository.save(new TenantData(tenantId, content));
    }
}
