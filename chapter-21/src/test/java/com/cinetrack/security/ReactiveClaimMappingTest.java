package com.cinetrack.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Collection;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ReactiveJwtAuthConverter}.
 *
 * No Spring context is loaded — the converter is a plain POJO and can be
 * tested by constructing a {@link Jwt} directly.
 *
 * These tests pin the authority-mapping contract:
 * <ul>
 *   <li>Space-delimited {@code scope} values become {@code SCOPE_}-prefixed authorities.</li>
 *   <li>A {@code tier} claim becomes a single {@code TIER_}-prefixed authority.</li>
 *   <li>Missing claims produce no authorities (no NPE, no empty-string authority).</li>
 * </ul>
 */
class ReactiveClaimMappingTest {

    private final ReactiveJwtAuthConverter converter = new ReactiveJwtAuthConverter();

    // ── scope claim ───────────────────────────────────────────────────────────

    @Test
    void scopeString_mapsToScopeAuthorities() {
        Jwt jwt = buildJwt(Map.of("scope", "catalog:read catalog:write"));

        AbstractAuthenticationToken token = converter.convert(jwt).block();

        assertThat(token).isNotNull();
        Collection<GrantedAuthority> authorities = token.getAuthorities();
        assertThat(authorities)
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("SCOPE_catalog:read", "SCOPE_catalog:write");
    }

    @Test
    void singleScope_producesOneAuthority() {
        Jwt jwt = buildJwt(Map.of("scope", "catalog:read"));

        AbstractAuthenticationToken token = converter.convert(jwt).block();

        assertThat(token).isNotNull();
        assertThat(token.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("SCOPE_catalog:read");
    }

    @Test
    void missingScope_producesNoScopeAuthorities() {
        Jwt jwt = buildJwt(Map.of());

        AbstractAuthenticationToken token = converter.convert(jwt).block();

        assertThat(token).isNotNull();
        assertThat(token.getAuthorities()).isEmpty();
    }

    // ── tier claim ────────────────────────────────────────────────────────────

    @Test
    void tierClaim_mapsToTierAuthority() {
        Jwt jwt = buildJwt(Map.of("tier", "ULTRA"));

        AbstractAuthenticationToken token = converter.convert(jwt).block();

        assertThat(token).isNotNull();
        assertThat(token.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("TIER_ULTRA");
    }

    @Test
    void tierPremium_mapsToTierPremiumAuthority() {
        Jwt jwt = buildJwt(Map.of("tier", "PREMIUM"));

        AbstractAuthenticationToken token = converter.convert(jwt).block();

        assertThat(token).isNotNull();
        assertThat(token.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("TIER_PREMIUM");
    }

    @Test
    void missingTier_producesNoTierAuthority() {
        Jwt jwt = buildJwt(Map.of("scope", "catalog:read"));

        AbstractAuthenticationToken token = converter.convert(jwt).block();

        assertThat(token).isNotNull();
        assertThat(token.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .noneMatch(a -> a.startsWith("TIER_"));
    }

    // ── combined scope + tier ─────────────────────────────────────────────────

    @Test
    void scopeAndTier_bothMapped() {
        Jwt jwt = buildJwt(Map.of(
                "scope", "catalog:read catalog:write",
                "tier", "ULTRA"
        ));

        AbstractAuthenticationToken token = converter.convert(jwt).block();

        assertThat(token).isNotNull();
        assertThat(token.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder(
                        "SCOPE_catalog:read",
                        "SCOPE_catalog:write",
                        "TIER_ULTRA"
                );
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private Jwt buildJwt(Map<String, Object> extraClaims) {
        Map<String, Object> headers = Map.of("alg", "RS256");

        Jwt.Builder builder = Jwt.withTokenValue("test-token")
                .headers(h -> h.putAll(headers))
                .issuer("https://auth1.cinetrack.io")
                .subject("test-user")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600));

        extraClaims.forEach(builder::claim);

        return builder.build();
    }
}
