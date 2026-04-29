package com.example.security.resourceserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, "/api/articles", "/api/articles/**")
                                .hasAnyAuthority("SCOPE_read", "ROLE_USER")
                        .requestMatchers(HttpMethod.POST, "/api/articles")
                                .hasAnyAuthority("SCOPE_write", "ROLE_ADMIN")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .csrf(csrf -> csrf.disable())
                .build();
    }

    /**
     * Extracts both standard OAuth2 scopes (SCOPE_*) and custom role claims (ROLE_*)
     * from the JWT so that hasAnyAuthority() works for both.
     */
    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Collection<GrantedAuthority> authorities = new ArrayList<>();

            // Standard scopes → SCOPE_read, SCOPE_write, …
            List<String> scopes = jwt.getClaimAsStringList("scope");
            if (scopes != null) {
                scopes.forEach(s -> authorities.add(new SimpleGrantedAuthority("SCOPE_" + s)));
            }

            // Custom roles claim → ROLE_USER, ROLE_ADMIN, …
            List<String> roles = jwt.getClaimAsStringList("roles");
            if (roles != null) {
                roles.forEach(r -> {
                    String authority = r.startsWith("ROLE_") ? r : "ROLE_" + r;
                    authorities.add(new SimpleGrantedAuthority(authority));
                });
            }

            return authorities;
        });
        return converter;
    }
}
