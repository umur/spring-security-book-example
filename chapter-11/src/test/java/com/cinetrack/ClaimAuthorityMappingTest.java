package com.cinetrack;

import com.cinetrack.security.CineTrackJwtConverter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for CineTrackJwtConverter in isolation.
 *
 * No Spring context — just the converter, a hand-built Jwt, and AssertJ.
 * This makes the tests fast and keeps the assertion surface tight:
 * we verify exactly which GrantedAuthority objects the converter produces
 * for each combination of claims.
 */
class ClaimAuthorityMappingTest {

    private CineTrackJwtConverter converter;

    @BeforeEach
    void setUp() {
        converter = new CineTrackJwtConverter();
    }

    // ---- scope claim --------------------------------------------------------

    @Test
    void spaceSeparatedScopeString_producesCorrectScopeAuthorities() {
        Jwt jwt = buildJwt(Map.of("scope", "catalog:read catalog:write"));

        Collection<GrantedAuthority> authorities = convert(jwt);

        assertThat(authorityNames(authorities))
                .containsExactlyInAnyOrder("SCOPE_catalog:read", "SCOPE_catalog:write");
    }

    @Test
    void singleScope_producesSingleScopeAuthority() {
        Jwt jwt = buildJwt(Map.of("scope", "catalog:read"));

        Collection<GrantedAuthority> authorities = convert(jwt);

        assertThat(authorityNames(authorities)).contains("SCOPE_catalog:read");
    }

    @Test
    void noScopeClaim_producesNoScopeAuthorities() {
        Jwt jwt = buildJwt(Map.of());

        Collection<GrantedAuthority> authorities = convert(jwt);

        assertThat(authorityNames(authorities))
                .noneMatch(name -> name.startsWith("SCOPE_"));
    }

    // ---- roles claim --------------------------------------------------------

    @Test
    void rolesArray_producesRoleAuthorities() {
        Jwt jwt = buildJwt(Map.of("roles", List.of("ADMIN", "MODERATOR")));

        Collection<GrantedAuthority> authorities = convert(jwt);

        assertThat(authorityNames(authorities))
                .containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_MODERATOR");
    }

    @Test
    void singleRole_producesSingleRoleAuthority() {
        Jwt jwt = buildJwt(Map.of("roles", List.of("ADMIN")));

        Collection<GrantedAuthority> authorities = convert(jwt);

        assertThat(authorityNames(authorities)).containsExactly("ROLE_ADMIN");
    }

    @Test
    void noRolesClaim_producesNoRoleAuthorities() {
        Jwt jwt = buildJwt(Map.of("scope", "catalog:read"));

        Collection<GrantedAuthority> authorities = convert(jwt);

        assertThat(authorityNames(authorities))
                .noneMatch(name -> name.startsWith("ROLE_"));
    }

    // ---- tier claim ---------------------------------------------------------

    @Test
    void premiumTier_producesTierPremiumAuthority() {
        Jwt jwt = buildJwt(Map.of("tier", "PREMIUM"));

        Collection<GrantedAuthority> authorities = convert(jwt);

        assertThat(authorityNames(authorities)).contains("TIER_PREMIUM");
    }

    @Test
    void standardTier_producesTierStandardAuthority() {
        Jwt jwt = buildJwt(Map.of("tier", "STANDARD"));

        Collection<GrantedAuthority> authorities = convert(jwt);

        assertThat(authorityNames(authorities)).contains("TIER_STANDARD");
    }

    @Test
    void noTierClaim_producesNoTierAuthority() {
        Jwt jwt = buildJwt(Map.of("scope", "catalog:read"));

        Collection<GrantedAuthority> authorities = convert(jwt);

        assertThat(authorityNames(authorities))
                .noneMatch(name -> name.startsWith("TIER_"));
    }

    // ---- combined claims ----------------------------------------------------

    @Test
    void allThreeClaimTypes_producesAllAuthorities() {
        Jwt jwt = buildJwt(Map.of(
                "scope", "catalog:read catalog:write",
                "roles", List.of("ADMIN"),
                "tier", "PREMIUM"
        ));

        Collection<GrantedAuthority> authorities = convert(jwt);

        assertThat(authorityNames(authorities))
                .containsExactlyInAnyOrder(
                        "SCOPE_catalog:read",
                        "SCOPE_catalog:write",
                        "ROLE_ADMIN",
                        "TIER_PREMIUM"
                );
    }

    // ---- helpers ------------------------------------------------------------

    private Jwt buildJwt(Map<String, Object> extraClaims) {
        Map<String, Object> headers = Map.of("alg", "RS256", "typ", "JWT");
        Map<String, Object> baseClaims = Map.of(
                "sub", "test-subject",
                "iss", "http://localhost:8080/issuer1",
                "iat", Instant.now(),
                "exp", Instant.now().plusSeconds(3600)
        );

        // Merge base claims with extra claims
        java.util.HashMap<String, Object> allClaims = new java.util.HashMap<>(baseClaims);
        allClaims.putAll(extraClaims);

        return Jwt.withTokenValue("test-token")
                .headers(h -> h.putAll(headers))
                .claims(c -> c.putAll(allClaims))
                .build();
    }

    private Collection<GrantedAuthority> convert(Jwt jwt) {
        AbstractAuthenticationToken token = converter.convert(jwt);
        assertThat(token).isNotNull();
        return token.getAuthorities();
    }

    private List<String> authorityNames(Collection<GrantedAuthority> authorities) {
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }
}
