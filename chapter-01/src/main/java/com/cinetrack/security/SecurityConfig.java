package com.cinetrack.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;

/**
 * Chapter 1 security configuration.
 *
 * Demonstrates the three primitives every Spring Security setup touches:
 *   1. The SecurityFilterChain: which requests need authentication
 *   2. The AuthenticationEntryPoint: what happens when they don't have it
 *   3. The authentication mechanism: form login + HTTP Basic in this chapter
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/api/movies/**").authenticated()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .defaultSuccessUrl("/api/movies", true)
            )
            .httpBasic(basic -> basic
                .authenticationEntryPoint(jsonUnauthorizedEntryPoint())
            )
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(jsonUnauthorizedEntryPoint())
            );

        return http.build();
    }

    /**
     * Returns a JSON body instead of the default WWW-Authenticate redirect/challenge,
     * so API clients get a machine-readable error rather than an HTML login page.
     */
    @Bean
    public AuthenticationEntryPoint jsonUnauthorizedEntryPoint() {
        return (HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\":\"Unauthorized\"}");
        };
    }
}
