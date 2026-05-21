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

import java.security.interfaces.RSAPublicKey;
import java.util.List;

/**
 * Generates an in-process RSA key pair that plays the role of a local
 * authorization server. In a real zero-trust deployment each service
 * fetches the authorization server's JWKS endpoint over HTTPS: we skip
 * that external dependency to keep the chapter self-contained.
 *
 * The same key is used by {@link com.cinetrack.catalog.CatalogController}
 * tests to mint signed tokens with the correct {@code aud} claim.
 */
@Configuration
public class JwkConfig {

    @Bean
    public RSAKey rsaKey() throws Exception {
        return new RSAKeyGenerator(2048)
                .keyID("cinetrack-ch22")
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

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    // ---- helpers --------------------------------------------------------

    private RSAPublicKey extractPublicKey(JWKSource<SecurityContext> source) {
        try {
            com.nimbusds.jose.jwk.JWKMatcher matcher = new com.nimbusds.jose.jwk.JWKMatcher.Builder().build();
            com.nimbusds.jose.jwk.JWKSelector selector = new com.nimbusds.jose.jwk.JWKSelector(matcher);
            List<com.nimbusds.jose.jwk.JWK> keys = source.get(selector, null);
            RSAKey rsaKey = (RSAKey) keys.get(0);
            return rsaKey.toRSAPublicKey();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot extract RSA public key", e);
        }
    }
}
