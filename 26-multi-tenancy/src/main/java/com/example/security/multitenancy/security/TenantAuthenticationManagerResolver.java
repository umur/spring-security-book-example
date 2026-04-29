package com.example.security.multitenancy.security;

import com.example.security.multitenancy.repository.TenantUserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves an {@link AuthenticationManager} per tenant so that credentials
 * are always validated against the correct tenant's user store.
 *
 * Managers are cached after first creation; a new manager is built for every
 * distinct tenant ID encountered.
 */
@Slf4j
@RequiredArgsConstructor
public class TenantAuthenticationManagerResolver
        implements AuthenticationManagerResolver<HttpServletRequest> {

    private final TenantUserRepository tenantUserRepository;
    private final PasswordEncoder passwordEncoder;

    private final Map<String, AuthenticationManager> managerCache = new ConcurrentHashMap<>();

    @Override
    public AuthenticationManager resolve(HttpServletRequest request) {
        String tenantId = TenantContext.getTenantId();
        if (tenantId == null || tenantId.isBlank()) {
            throw new BadCredentialsException("No tenant context available for authentication");
        }
        return managerCache.computeIfAbsent(tenantId, this::buildManagerForTenant);
    }

    private AuthenticationManager buildManagerForTenant(String tenantId) {
        log.debug("Building AuthenticationManager for tenant '{}'", tenantId);
        var uds = new com.example.security.multitenancy.service.TenantUserDetailsService(
                tenantUserRepository, tenantId);
        var provider = new DaoAuthenticationProvider(uds);
        provider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(provider);
    }
}
