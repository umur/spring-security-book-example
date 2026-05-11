package com.cinetrack.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

/**
 * Generates a fresh RSA-2048 key pair at startup and wires it into:
 * <ul>
 *   <li>{@link ReactiveJwtDecoder} — used by the reactive resource server to
 *       validate incoming Bearer tokens without blocking a thread.</li>
 *   <li>{@link JwtEncoder} — used by tests to mint valid tokens without an
 *       external authorization server.</li>
 * </ul>
 *
 * In production you load the public key from the authorization server's JWKS
 * endpoint. Generating the key pair here keeps the chapter self-contained.
 */
@Configuration
public class JwkConfig {

    @Bean
    public RSAKey rsaKey() throws Exception {
        return new RSAKeyGenerator(2048)
                .keyID("cinetrack-ch20")
                .generate();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder(RSAKey rsaKey) throws Exception {
        return NimbusReactiveJwtDecoder
                .withPublicKey(rsaKey.toRSAPublicKey())
                .build();
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }
}
