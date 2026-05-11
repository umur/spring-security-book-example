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

/**
 * Produces two independent RSA key pairs — one for each issuer (tenant).
 *
 * issuer1Key  →  simulates the "CineTrack internal" authorization server
 * issuer2Key  →  simulates a "partner" authorization server (e.g. a studio SSO)
 *
 * In production each issuer publishes its own JWKS endpoint. Here we hold
 * both keys in memory so the multi-tenant test can mint tokens for either
 * issuer without standing up a real AS.
 *
 * Beans are named explicitly so SecurityConfig can wire the correct decoder
 * to each issuer's authentication manager.
 */
@Configuration
public class JwkConfig {

    @Bean
    public RSAKey issuer1Key() throws Exception {
        return new RSAKeyGenerator(2048)
                .keyID("issuer1-key")
                .generate();
    }

    @Bean
    public RSAKey issuer2Key() throws Exception {
        return new RSAKeyGenerator(2048)
                .keyID("issuer2-key")
                .generate();
    }

    @Bean
    public JWKSource<SecurityContext> issuer1JwkSource(RSAKey issuer1Key) {
        return new ImmutableJWKSet<>(new JWKSet(issuer1Key));
    }

    @Bean
    public JWKSource<SecurityContext> issuer2JwkSource(RSAKey issuer2Key) {
        return new ImmutableJWKSet<>(new JWKSet(issuer2Key));
    }

    @Bean
    public JwtDecoder issuer1JwtDecoder(RSAKey issuer1Key) throws Exception {
        RSAPublicKey publicKey = issuer1Key.toRSAPublicKey();
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    @Bean
    public JwtDecoder issuer2JwtDecoder(RSAKey issuer2Key) throws Exception {
        RSAPublicKey publicKey = issuer2Key.toRSAPublicKey();
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    @Bean
    public JwtEncoder issuer1JwtEncoder(JWKSource<SecurityContext> issuer1JwkSource) {
        return new NimbusJwtEncoder(issuer1JwkSource);
    }

    @Bean
    public JwtEncoder issuer2JwtEncoder(JWKSource<SecurityContext> issuer2JwkSource) {
        return new NimbusJwtEncoder(issuer2JwkSource);
    }
}
