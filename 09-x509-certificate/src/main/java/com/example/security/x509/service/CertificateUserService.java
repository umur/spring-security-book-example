package com.example.security.x509.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * Maps certificate Common Names (CNs) to {@link UserDetails} with roles.
 *
 * In production this would query a database or LDAP directory.
 * For this example known CNs and their roles are hard-coded to keep the
 * module self-contained and runnable without external infrastructure.
 *
 * CN extraction from the certificate SubjectDN is handled by Spring Security's
 * {@code SubjectDnX509PrincipalExtractor} which is configured in
 * {@code SecurityConfig}. The extracted CN is passed as the {@code username}
 * argument to this method.
 */
@Slf4j
@Service
public class CertificateUserService implements UserDetailsService {

    /**
     * Well-known certificate CNs and their assigned roles.
     * Keys are certificate CNs, values are Spring Security role names (without ROLE_ prefix).
     */
    private static final Map<String, List<String>> KNOWN_CERTIFICATES = Map.of(
            "client-user",  List.of("USER"),
            "client-admin", List.of("USER", "ADMIN"),
            "service-a",    List.of("USER")
    );

    @Override
    public UserDetails loadUserByUsername(String cn) throws UsernameNotFoundException {
        log.debug("Loading user details for certificate CN='{}'", cn);

        if (!KNOWN_CERTIFICATES.containsKey(cn)) {
            log.warn("Certificate CN='{}' is not registered — access denied", cn);
            throw new UsernameNotFoundException("Certificate CN not registered: " + cn);
        }

        List<SimpleGrantedAuthority> authorities = KNOWN_CERTIFICATES.get(cn).stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .toList();

        // X.509 authentication does not use passwords; a non-null placeholder is required.
        return new User(cn, "", authorities);
    }
}
