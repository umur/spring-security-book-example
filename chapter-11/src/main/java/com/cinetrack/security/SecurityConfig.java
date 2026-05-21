package com.cinetrack.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;

import java.util.HashMap;
import java.util.Map;

/**
 * Multi-tenant resource server configuration.
 *
 * CineTrack accepts tokens from two issuers:
 *   issuer1: the internal CineTrack authorization server
 *   issuer2: a partner authorization server (e.g. a studio SSO)
 *
 * JwtIssuerAuthenticationManagerResolver reads the iss claim from the
 * incoming token and routes it to the correct JwtDecoder. This avoids
 * accepting tokens across tenants: a token signed by issuer2's key is
 * rejected by issuer1's decoder and vice versa.
 *
 * Authorization rules:
 *   /api/catalog/**  →  SCOPE_catalog:read
 *   /api/admin/**    →  ROLE_ADMIN
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${cinetrack.security.issuer1-uri}")
    private String issuer1Uri;

    @Value("${cinetrack.security.issuer2-uri}")
    private String issuer2Uri;

    private final CineTrackJwtConverter jwtConverter;

    public SecurityConfig(CineTrackJwtConverter jwtConverter) {
        this.jwtConverter = jwtConverter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtDecoder issuer1JwtDecoder,
            JwtDecoder issuer2JwtDecoder
    ) throws Exception {

        JwtIssuerAuthenticationManagerResolver resolver =
                buildIssuerResolver(issuer1JwtDecoder, issuer2JwtDecoder);

        http
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/catalog/**").hasAuthority("SCOPE_catalog:read")
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .authenticationManagerResolver(resolver)
            );

        return http.build();
    }

    /**
     * Maps issuer URI strings to their respective AuthenticationManagers.
     *
     * Each JwtAuthenticationProvider wraps a decoder and applies the
     * CineTrackJwtConverter so all three claim types (scope/roles/tier)
     * are extracted into authorities regardless of which issuer signed the token.
     */
    private JwtIssuerAuthenticationManagerResolver buildIssuerResolver(
            JwtDecoder issuer1JwtDecoder,
            JwtDecoder issuer2JwtDecoder
    ) {
        Map<String, AuthenticationManager> managers = new HashMap<>();

        JwtAuthenticationProvider provider1 = new JwtAuthenticationProvider(issuer1JwtDecoder);
        provider1.setJwtAuthenticationConverter(jwtConverter);
        managers.put(issuer1Uri, provider1::authenticate);

        JwtAuthenticationProvider provider2 = new JwtAuthenticationProvider(issuer2JwtDecoder);
        provider2.setJwtAuthenticationConverter(jwtConverter);
        managers.put(issuer2Uri, provider2::authenticate);

        return new JwtIssuerAuthenticationManagerResolver(managers::get);
    }
}
