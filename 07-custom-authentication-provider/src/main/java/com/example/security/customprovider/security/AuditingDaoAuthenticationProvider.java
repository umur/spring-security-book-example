package com.example.security.customprovider.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Custom subclass of {@link DaoAuthenticationProvider} that adds audit logging
 * for every authentication attempt against the database user store.
 */
@Slf4j
public class AuditingDaoAuthenticationProvider extends DaoAuthenticationProvider {

    public AuditingDaoAuthenticationProvider(UserDetailsService userDetailsService,
                                              PasswordEncoder passwordEncoder) {
        super(userDetailsService);
        setPasswordEncoder(passwordEncoder);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        log.info("DB authentication attempt for user '{}'", username);
        try {
            Authentication result = super.authenticate(authentication);
            log.info("DB authentication succeeded for user '{}' with authorities {}",
                    username, result.getAuthorities());
            return result;
        } catch (BadCredentialsException ex) {
            log.warn("DB authentication failed for user '{}': bad credentials", username);
            throw ex;
        } catch (AuthenticationException ex) {
            log.warn("DB authentication failed for user '{}': {}", username, ex.getMessage());
            throw ex;
        }
    }
}
