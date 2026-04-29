package com.example.security.multitenancy.config;

import com.example.security.multitenancy.filter.TenantResolutionFilter;
import com.example.security.multitenancy.repository.TenantUserRepository;
import com.example.security.multitenancy.security.TenantAuthenticationManagerResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;

import java.time.Instant;

/**
 * Security configuration for multi-tenant HTTP Basic authentication.
 *
 * Key design decisions:
 * - {@link TenantResolutionFilter} runs first — it rejects requests without
 *   {@code X-Tenant-ID} before Spring Security processing begins.
 * - {@link TenantAuthenticationManagerResolver} picks the correct
 *   per-tenant {@code AuthenticationManager} for every request so that
 *   credential lookups are always tenant-scoped.
 * - Sessions are stateless; CSRF is disabled.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final TenantUserRepository tenantUserRepository;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        var tenantFilter = new TenantResolutionFilter();
        var resolver = new TenantAuthenticationManagerResolver(tenantUserRepository, passwordEncoder());

        // AuthenticationFilter supports AuthenticationManagerResolver directly;
        // this replaces the removed HttpSecurity.authenticationManagerResolver() API
        // (which no longer exists on HttpSecurity in Spring Security 7).
        var basicConverter = new BasicAuthenticationConverter();
        var basicAuthFilter = new AuthenticationFilter(resolver, basicConverter);
        // For stateless APIs the success handler must continue the filter chain rather
        // than redirecting (the SavedRequestAwareAuthenticationSuccessHandler default
        // would send a redirect which breaks REST clients).
        // An anonymous class is required because AuthenticationSuccessHandler has an
        // abstract 3-arg method; the 4-arg chain-aware method is a default — a lambda
        // would be bound to the abstract 3-arg form and never receive the FilterChain.
        basicAuthFilter.setSuccessHandler(new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request,
                                                HttpServletResponse response,
                                                Authentication authentication) {
                // Not called — the 4-arg override below handles chain continuation.
            }

            @Override
            public void onAuthenticationSuccess(HttpServletRequest request,
                                                HttpServletResponse response,
                                                FilterChain chain,
                                                Authentication authentication) throws java.io.IOException, jakarta.servlet.ServletException {
                chain.doFilter(request, response);
            }
        });
        // Leave the default failure handler (AuthenticationEntryPointFailureHandler wrapping
        // HttpStatusEntryPoint(UNAUTHORIZED)) so bad credentials → 401, not 500.

        return http
                .addFilterBefore(tenantFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(basicAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/api/data").authenticated()
                        .requestMatchers("/api/tenant/info").authenticated()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .csrf(csrf -> csrf.disable())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(HttpStatus.UNAUTHORIZED.value());
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            response.getWriter().write(
                                    "{\"error\":\"Unauthorized\",\"message\":\"Authentication required\",\"timestamp\":\"" + Instant.now() + "\"}"
                            );
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setStatus(HttpStatus.FORBIDDEN.value());
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            response.getWriter().write(
                                    "{\"error\":\"Forbidden\",\"message\":\"Insufficient permissions\",\"timestamp\":\"" + Instant.now() + "\"}"
                            );
                        })
                )
                .build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
