package com.example.security.multitenancy.service;

import com.example.security.multitenancy.repository.TenantUserRepository;
import com.example.security.multitenancy.security.TenantContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;

/**
 * Tenant-scoped {@link UserDetailsService} that resolves users by looking up
 * both the tenant ID (from {@link TenantContext}) and the username together.
 * The same username can exist in different tenants as independent identities.
 */
@Slf4j
@RequiredArgsConstructor
public class TenantUserDetailsService implements UserDetailsService {

    private final TenantUserRepository tenantUserRepository;
    private final String tenantId;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return tenantUserRepository.findByTenantIdAndUsername(tenantId, username)
                .map(u -> new User(
                        u.getUsername(),
                        u.getPassword(),
                        u.isEnabled(), true, true, true,
                        List.of(new SimpleGrantedAuthority("ROLE_" + u.getRole()))
                ))
                .orElseThrow(() -> {
                    log.debug("User '{}' not found in tenant '{}'", username, tenantId);
                    return new UsernameNotFoundException(
                            "User '" + username + "' not found in tenant '" + tenantId + "'");
                });
    }
}
