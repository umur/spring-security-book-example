package com.cinetrack.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import java.util.List;

/**
 * Builds a SecurityContext from {@link WithCineTrackUser} annotation attributes.
 *
 * The principal is a {@link CineTrackPrincipal} record, so controllers that
 * inject {@code @AuthenticationPrincipal CineTrackPrincipal} receive the exact
 * values supplied in the annotation without any JWT or session involved.
 */
public class WithCineTrackUserSecurityContextFactory
        implements WithSecurityContextFactory<WithCineTrackUser> {

    @Override
    public SecurityContext createSecurityContext(WithCineTrackUser annotation) {
        CineTrackPrincipal principal = new CineTrackPrincipal(
                annotation.userId(),
                annotation.email(),
                annotation.tier()
        );

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        principal,
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_USER"))
                );

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        return context;
    }
}
