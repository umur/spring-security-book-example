package com.cinetrack.security;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.security.interfaces.RSAPublicKey;
import java.util.List;

/**
 * In-process RSA key pair for signing and verifying JWTs in tests.
 *
 * Generates a fresh 2048-bit key at startup. The public component is exposed
 * via a JwtDecoder bean so the resource server can verify tokens signed with
 * the matching private key — all in-process, no authorization server needed.
 *
 * WireMockJwksTest replaces this decoder with one that fetches the JWKS from
 * WireMock, exercising the full network fetch-and-validate path.
 */
@Configuration
public class JwkConfig {

    @Bean
    public RSAKey rsaKey() throws Exception {
        return new RSAKeyGenerator(2048)
                .keyID("cinetrack-ch23")
                .generate();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
        JWKSet set = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(set);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        RSAPublicKey publicKey = extractPublicKey(jwkSource);
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    // ---- helpers --------------------------------------------------------

    private RSAPublicKey extractPublicKey(JWKSource<SecurityContext> source) {
        try {
            JWKMatcher matcher = new JWKMatcher.Builder().build();
            JWKSelector selector = new JWKSelector(matcher);
            List<JWK> keys = source.get(selector, null);
            RSAKey rsaKey = (RSAKey) keys.get(0);
            return rsaKey.toRSAPublicKey();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot extract RSA public key", e);
        }
    }
}
