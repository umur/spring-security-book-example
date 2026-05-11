package com.cinetrack.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/**
 * Generates a fresh RSA-2048 key pair at startup and wires it into both the
 * encoder (used by TokenController to mint tokens) and the decoder (used by
 * the resource server to validate incoming Bearer tokens).
 *
 * In production you load the key from a secrets manager — generating it here
 * keeps the chapter self-contained without an external authorization server.
 */
@Configuration
public class JwkConfig {

    @Bean
    public RSAKey rsaKey() throws Exception {
        return new RSAKeyGenerator(2048)
                .keyID("cinetrack-ch10")
                .generate();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
        JWKSet set = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(set);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return NimbusJwtDecoder.withPublicKey(
                rsaKeyPublic(jwkSource)
        ).build();
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    // ---- helpers --------------------------------------------------------

    private java.security.interfaces.RSAPublicKey rsaKeyPublic(JWKSource<SecurityContext> source) {
        try {
            com.nimbusds.jose.jwk.JWKMatcher matcher = new com.nimbusds.jose.jwk.JWKMatcher.Builder().build();
            com.nimbusds.jose.jwk.JWKSelector selector = new com.nimbusds.jose.jwk.JWKSelector(matcher);
            java.util.List<com.nimbusds.jose.jwk.JWK> keys = source.get(selector, null);
            RSAKey rsaKey = (RSAKey) keys.get(0);
            return rsaKey.toRSAPublicKey();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot extract RSA public key", e);
        }
    }
}
