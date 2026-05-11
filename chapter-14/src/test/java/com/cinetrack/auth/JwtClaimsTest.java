package com.cinetrack.auth;

import com.cinetrack.security.TokenCustomizerConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Chapter 14: Unit tests for the OAuth2TokenCustomizer logic.
 *
 * Tests the customizer in isolation by mocking JwtEncodingContext.
 * This is faster than a full SpringBootTest and pinpoints exactly
 * which conditional branch the customizer took.
 *
 * In Spring Security 7, JwtClaimsSet.Builder is a final class rather than
 * an interface, so we mock it via Mockito and capture claim() / claims()
 * invocations into a plain map for assertion.
 */
class JwtClaimsTest {

    private OAuth2TokenCustomizer<JwtEncodingContext> customizer;

    @BeforeEach
    void setUp() {
        customizer = new TokenCustomizerConfig().tokenCustomizer();
    }

    /**
     * An access token for a user with ROLE_USER must receive the "roles" claim
     * containing "USER" (the prefix is stripped by the customizer).
     */
    @Test
    void accessToken_withUserPrincipal_addsRolesClaim() {
        Map<String, Object> captured = new LinkedHashMap<>();
        JwtClaimsSet.Builder claimsBuilder = capturingBuilder(captured);

        Authentication principal = mock(Authentication.class);
        when(principal.getAuthorities()).thenAnswer(inv ->
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
        when(principal.getName()).thenReturn("alice");

        JwtEncodingContext context = mock(JwtEncodingContext.class);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
        when(context.getPrincipal()).thenReturn(principal);
        when(context.getClaims()).thenReturn(claimsBuilder);

        customizer.customize(context);

        assertThat(captured).containsKey("roles");
        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) captured.get("roles");
        assertThat(roles).containsExactly("USER");
    }

    /**
     * ID tokens are the OIDC identity assertion, not an API credential.
     * The customizer must leave them completely untouched — getClaims()
     * is never called when the token type is id_token.
     */
    @Test
    void idToken_isNotModified() {
        Map<String, Object> captured = new LinkedHashMap<>();

        JwtEncodingContext context = mock(JwtEncodingContext.class);
        when(context.getTokenType()).thenReturn(new OAuth2TokenType(OidcParameterNames.ID_TOKEN));

        customizer.customize(context);

        assertThat(captured).isEmpty();
    }

    // -------------------------------------------------------------------------

    /**
     * Builds a Mockito mock of JwtClaimsSet.Builder that records every
     * claim(name, value) invocation and every claims(consumer) call into the
     * supplied map. Other Builder methods return the mock so chained calls
     * still compile, but their inputs are ignored.
     */
    @SuppressWarnings("unchecked")
    private static JwtClaimsSet.Builder capturingBuilder(Map<String, Object> store) {
        JwtClaimsSet.Builder builder = mock(JwtClaimsSet.Builder.class);
        when(builder.claim(anyString(), any())).thenAnswer(inv -> {
            store.put(inv.getArgument(0), inv.getArgument(1));
            return builder;
        });
        when(builder.claims(any(Consumer.class))).thenAnswer(inv -> {
            Consumer<Map<String, Object>> consumer = inv.getArgument(0);
            consumer.accept(store);
            return builder;
        });
        return builder;
    }
}
