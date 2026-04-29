package com.example.security.customprovider.security;

import com.example.security.customprovider.repository.DomainTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * AuthenticationProvider that validates domain tokens stored in the database.
 *
 * Supports only {@link DomainTokenAuthenticationToken}. Looks up the token
 * value in the {@link DomainTokenRepository} and rejects expired or unknown tokens.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DomainTokenAuthenticationProvider implements AuthenticationProvider {

    private final DomainTokenRepository domainTokenRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String rawToken = (String) authentication.getPrincipal();

        var domainToken = domainTokenRepository.findByTokenValue(rawToken)
                .orElseThrow(() -> {
                    log.warn("Domain token authentication failed: token not found");
                    return new BadCredentialsException("Invalid domain token");
                });

        if (domainToken.isExpired()) {
            log.warn("Domain token authentication failed: token expired for user '{}'", domainToken.getUsername());
            throw new BadCredentialsException("Domain token has expired");
        }

        log.info("Domain token authentication succeeded for user '{}' with role '{}'",
                domainToken.getUsername(), domainToken.getRole());

        var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + domainToken.getRole()));
        return new DomainTokenAuthenticationToken(domainToken.getUsername(), null, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return DomainTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
