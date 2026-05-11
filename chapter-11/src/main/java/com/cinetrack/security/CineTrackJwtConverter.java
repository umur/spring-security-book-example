package com.cinetrack.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * Custom JWT → AbstractAuthenticationToken converter.
 *
 * Spring Security's default converter only handles the scope claim. CineTrack
 * JWTs carry additional claims that drive authorization decisions:
 *
 *   scope  →  "catalog:read catalog:write"  →  SCOPE_catalog:read, SCOPE_catalog:write
 *   roles  →  ["ADMIN", "MODERATOR"]        →  ROLE_ADMIN, ROLE_MODERATOR
 *   tier   →  "PREMIUM"                     →  TIER_PREMIUM
 *
 * Each prefix makes the authority's origin explicit in access rules, e.g.:
 *   hasAuthority("ROLE_ADMIN") vs hasAuthority("SCOPE_catalog:read")
 *
 * The converter is registered as a @Component so SecurityConfig can inject it
 * directly rather than constructing it inline in the lambda.
 */
@Component
public class CineTrackJwtConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();

        authorities.addAll(extractScopeAuthorities(jwt));
        authorities.addAll(extractRoleAuthorities(jwt));
        authorities.addAll(extractTierAuthority(jwt));

        return new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());
    }

    /**
     * Splits the space-separated scope claim and prefixes each value with SCOPE_.
     * Handles both a String claim ("catalog:read catalog:write") and a List claim.
     */
    private List<GrantedAuthority> extractScopeAuthorities(Jwt jwt) {
        Object scopeClaim = jwt.getClaim("scope");
        if (scopeClaim == null) {
            return List.of();
        }

        List<String> scopes;
        if (scopeClaim instanceof String scopeString) {
            scopes = Arrays.asList(scopeString.split(" "));
        } else if (scopeClaim instanceof List<?> scopeList) {
            scopes = scopeList.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .toList();
        } else {
            return List.of();
        }

        return scopes.stream()
                .filter(s -> !s.isBlank())
                .map(s -> new SimpleGrantedAuthority("SCOPE_" + s))
                .map(GrantedAuthority.class::cast)
                .toList();
    }

    /**
     * Extracts the roles claim (a JSON array of strings) and prefixes with ROLE_.
     */
    private List<GrantedAuthority> extractRoleAuthorities(Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList("roles");
        if (roles == null) {
            return List.of();
        }

        return roles.stream()
                .filter(r -> !r.isBlank())
                .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                .map(GrantedAuthority.class::cast)
                .toList();
    }

    /**
     * Extracts the tier claim (a single string) and prefixes with TIER_.
     * TIER_PREMIUM can gate access to 4K streams, offline downloads, etc.
     */
    private List<GrantedAuthority> extractTierAuthority(Jwt jwt) {
        String tier = jwt.getClaimAsString("tier");
        if (tier == null || tier.isBlank()) {
            return List.of();
        }

        return List.of(new SimpleGrantedAuthority("TIER_" + tier));
    }
}
