package com.example.security.customprovider.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Custom Authentication token for domain token-based authentication.
 *
 * Pre-authentication: principal = raw token string, credentials = raw token string, authorities = empty.
 * Post-authentication: principal = username, credentials = null, authorities = populated.
 */
public class DomainTokenAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;
    private Object credentials;

    /** Constructor for unauthenticated token (pre-authentication). */
    public DomainTokenAuthenticationToken(String rawToken) {
        super(java.util.Collections.emptyList());
        this.principal = rawToken;
        this.credentials = rawToken;
        setAuthenticated(false);
    }

    /** Constructor for authenticated token (post-authentication). */
    public DomainTokenAuthenticationToken(Object principal,
                                          Object credentials,
                                          Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.credentials = null;
    }
}
