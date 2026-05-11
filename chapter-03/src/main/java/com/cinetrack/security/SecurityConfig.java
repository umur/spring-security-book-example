package com.cinetrack.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Chapter 3 security configuration — JWT resource server.
 *
 * Key decisions:
 *   - oauth2ResourceServer with JWT: every request must carry a valid bearer token.
 *   - Scope-based authorization: {@code catalog:read} gates the movie catalog.
 *   - STATELESS sessions and disabled CSRF: tokens are self-contained credentials.
 *   - Token issuance via {@code /api/token} is permitted without a token (test helper).
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtDecoder jwtDecoder;

    public SecurityConfig(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/token").permitAll()
                .requestMatchers("/api/movies/**").hasAuthority("SCOPE_catalog:read")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.decoder(jwtDecoder))
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .csrf(csrf -> csrf.disable());

        return http.build();
    }
}
