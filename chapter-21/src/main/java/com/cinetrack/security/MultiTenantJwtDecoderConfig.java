package com.cinetrack.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Multi-tenant JWT configuration for chapter 21.
 *
 * Two test issuers are registered, each with its own RSA key pair. In production
 * each issuer URI would point to a real authorization server's JWKS endpoint via
 * {@link NimbusReactiveJwtDecoder#withJwkSetUri(String)}.
 *
 * The {@link ReactiveAuthenticationManagerResolver} extracts the {@code iss}
 * claim from the token, finds the matching decoder, and returns the corresponding
 * {@link ReactiveAuthenticationManager}. If the issuer is unknown, the resolver
 * returns {@link Mono#empty()}, which triggers a 401.
 *
 * Key insight: the resolver itself is reactive — it can perform non-blocking I/O
 * (e.g. a Redis lookup for dynamic tenant registration) before returning the
 * manager.
 */
@Configuration
public class MultiTenantJwtDecoderConfig {

    static final String ISSUER_1 = "https://auth1.cinetrack.io";
    static final String ISSUER_2 = "https://auth2.cinetrack.io";

    @Bean
    public RSAKey rsaKeyIssuer1() throws Exception {
        return new RSAKeyGenerator(2048)
                .keyID("cinetrack-ch21-issuer1")
                .generate();
    }

    @Bean
    public RSAKey rsaKeyIssuer2() throws Exception {
        return new RSAKeyGenerator(2048)
                .keyID("cinetrack-ch21-issuer2")
                .generate();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSourceIssuer1(RSAKey rsaKeyIssuer1) {
        return new ImmutableJWKSet<>(new JWKSet(rsaKeyIssuer1));
    }

    @Bean
    public JWKSource<SecurityContext> jwkSourceIssuer2(RSAKey rsaKeyIssuer2) {
        return new ImmutableJWKSet<>(new JWKSet(rsaKeyIssuer2));
    }

    @Bean
    public ReactiveJwtDecoder jwtDecoderIssuer1(RSAKey rsaKeyIssuer1) throws Exception {
        return NimbusReactiveJwtDecoder
                .withPublicKey(rsaKeyIssuer1.toRSAPublicKey())
                .build();
    }

    @Bean
    public ReactiveJwtDecoder jwtDecoderIssuer2(RSAKey rsaKeyIssuer2) throws Exception {
        return NimbusReactiveJwtDecoder
                .withPublicKey(rsaKeyIssuer2.toRSAPublicKey())
                .build();
    }

    /**
     * Resolves the correct {@link ReactiveAuthenticationManager} by matching the
     * {@code iss} claim in the Bearer token against the known issuer map.
     *
     * The resolver is called once per request, before the JWT is fully validated.
     * Spring Security extracts the issuer from the (unverified) token header/body
     * solely to pick the right key — the signature is verified afterwards.
     */
    @Bean
    public ReactiveAuthenticationManagerResolver<ServerWebExchange> authManagerResolver(
            ReactiveJwtDecoder jwtDecoderIssuer1,
            ReactiveJwtDecoder jwtDecoderIssuer2,
            ReactiveJwtAuthConverter jwtAuthConverter) {

        Map<String, ReactiveAuthenticationManager> managers = Map.of(
                ISSUER_1, buildManager(jwtDecoderIssuer1, jwtAuthConverter),
                ISSUER_2, buildManager(jwtDecoderIssuer2, jwtAuthConverter)
        );

        return exchange -> resolveFromBearerToken(exchange, managers);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private ReactiveAuthenticationManager buildManager(
            ReactiveJwtDecoder decoder,
            ReactiveJwtAuthConverter converter) {
        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(decoder);
        manager.setJwtAuthenticationConverter(converter);
        return manager;
    }

    /**
     * Extracts the {@code iss} claim from the raw Bearer token (without
     * verifying the signature) and looks up the corresponding manager.
     *
     * Uses {@link com.nimbusds.jwt.JWTParser} to peek at the claims before
     * cryptographic validation — this is safe because we only use the issuer
     * to select the right key; the signature check happens inside the manager.
     */
    private Mono<ReactiveAuthenticationManager> resolveFromBearerToken(
            ServerWebExchange exchange,
            Map<String, ReactiveAuthenticationManager> managers) {

        return Mono.fromCallable(() -> {
            String authHeader = exchange.getRequest().getHeaders()
                    .getFirst("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return null;
            }
            String token = authHeader.substring(7);
            com.nimbusds.jwt.JWT parsed = com.nimbusds.jwt.JWTParser.parse(token);
            String issuer = parsed.getJWTClaimsSet().getIssuer();
            return managers.get(issuer);
        });
    }
}
