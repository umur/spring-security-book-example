package com.cinetrack.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Chapter 17 security configuration.
 *
 * HTTP Basic is sufficient for tests — the interesting decisions are at the method
 * level, not at the URL level. {@code @EnableMethodSecurity} activates the AOP
 * proxies that enforce {@code @PreAuthorize}, {@code @PostAuthorize}, and
 * {@code @PostFilter} on service methods.
 *
 * Users:
 *   - alice  — ROLE_VIEWER + TIER_PREMIUM  (can access premium content)
 *   - bob    — ROLE_VIEWER + TIER_BASIC    (cannot access premium content)
 *   - admin  — ROLE_ADMIN  + ROLE_VIEWER   (bypasses all ownership checks)
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/**").authenticated()
                .anyRequest().authenticated()
            )
            .httpBasic(basic -> {})
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .csrf(csrf -> csrf.disable());

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        var alice = User.withDefaultPasswordEncoder()
                .username("alice")
                .password("password")
                .roles("VIEWER")
                .authorities("ROLE_VIEWER", "TIER_PREMIUM")
                .build();

        var bob = User.withDefaultPasswordEncoder()
                .username("bob")
                .password("password")
                .roles("VIEWER")
                .authorities("ROLE_VIEWER", "TIER_BASIC")
                .build();

        var admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("admin")
                .roles("ADMIN", "VIEWER")
                .build();

        return new InMemoryUserDetailsManager(alice, bob, admin);
    }
}
