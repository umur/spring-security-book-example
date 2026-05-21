package com.cinetrack.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security configuration covering every testing strategy shown in Chapter 23.
 *
 * Authorization rules:
 *   GET  /api/catalog/movies/**  → SCOPE_catalog:read (JWT)
 *   POST /api/catalog/movies     → ROLE_ADMIN (JWT)
 *   DELETE /api/catalog/movies/**→ ROLE_ADMIN (JWT)
 *   /api/movies/**               → ROLE_USER or ROLE_ADMIN (Basic or JWT)
 *   /api/admin/**                → ROLE_ADMIN
 *   /api/subscriptions/**        → FACTOR_TOTP (step-up demo)
 *   anyRequest                   → authenticated
 *
 * Both HTTP Basic and JWT resource server are active so MockMvc tests can
 * exercise httpBasic(), @WithMockUser, jwt(), and @WithCineTrackUser in one app.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.GET, "/api/catalog/movies/**").hasAuthority("SCOPE_catalog:read")
                .requestMatchers(HttpMethod.POST, "/api/catalog/movies").hasRole("ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/api/catalog/movies/**").hasRole("ADMIN")
                .requestMatchers("/api/movies/**").hasAnyRole("USER", "ADMIN")
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/subscriptions/**").hasAuthority("FACTOR_TOTP")
                .anyRequest().authenticated()
            )
            .httpBasic(basic -> {})
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> {})
            )
            .csrf(csrf -> csrf.disable());

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        var alice = User.builder()
                .username("alice")
                .password(passwordEncoder.encode("alice123"))
                .roles("USER")
                .build();

        var admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("admin123"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(alice, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
