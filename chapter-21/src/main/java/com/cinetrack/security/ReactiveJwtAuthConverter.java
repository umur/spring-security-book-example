package com.cinetrack.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * Reactive JWT authentication converter for CineTrack.
 *
 * Spring Security's default converter maps the {@code scope} claim to
 * {@code SCOPE_}-prefixed authorities. This converter extends that behaviour
 * with a second custom claim — {@code tier} — which maps to {@code TIER_}-
 * prefixed authorities used for subscription-level gating.
 *
 * Example input claims:
 * <pre>
 *   "scope": "catalog:read catalog:write"
 *   "tier":  "ULTRA"
 * </pre>
 *
 * Resulting authorities:
 * <pre>
 *   SCOPE_catalog:read
 *   SCOPE_catalog:write
 *   TIER_ULTRA
 * </pre>
 *
 * Implementing {@code Converter<Jwt, Mono<AbstractAuthenticationToken>>} keeps
 * the converter compatible with the reactive {@link JwtReactiveAuthenticationManager}.
 */
@Component
public class ReactiveJwtAuthConverter
        implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {

    @Override
    public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        JwtAuthenticationToken token = new JwtAuthenticationToken(jwt, authorities);
        return Mono.just(token);
    }

    // ── claim extraction ──────────────────────────────────────────────────────

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.addAll(scopeAuthorities(jwt));
        authorities.addAll(tierAuthority(jwt));
        return authorities;
    }

    /**
     * Maps space-delimited scope values to {@code SCOPE_}-prefixed authorities.
     *
     * Handles both a {@code String} claim (space-delimited) and a
     * {@code List<String>} claim, since different authorization servers use
     * different serialisation formats.
     */
    private List<GrantedAuthority> scopeAuthorities(Jwt jwt) {
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
     * Maps the {@code tier} claim to a single {@code TIER_}-prefixed authority.
     *
     * The tier claim is a single string representing the user's subscription
     * level — e.g. {@code "ULTRA"}, {@code "PREMIUM"}, or {@code "FREE"}.
     */
    private List<GrantedAuthority> tierAuthority(Jwt jwt) {
        String tier = jwt.getClaimAsString("tier");
        if (tier == null || tier.isBlank()) {
            return List.of();
        }
        return List.of(new SimpleGrantedAuthority("TIER_" + tier));
    }
}
