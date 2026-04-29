package com.example.security.mfa.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Authentication token representing a fully MFA-verified user.
 */
public class MfaAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;

    private MfaAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        setAuthenticated(true);
    }

    public static MfaAuthenticationToken authenticated(Object principal,
                                                        Collection<? extends GrantedAuthority> authorities) {
        return new MfaAuthenticationToken(principal, authorities);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
