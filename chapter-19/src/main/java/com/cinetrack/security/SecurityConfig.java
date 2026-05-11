package com.cinetrack.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

/**
 * Chapter 19 security configuration.
 *
 * Two non-trivial authorization rules are registered:
 *
 * 1. {@code /api/catalog/**} GET — delegated to {@link SubscriptionTierAuthorizationManager},
 *    which inspects the path suffix to decide whether TIER_PREMIUM is required.
 *    Using a custom {@code AuthorizationManager} keeps the policy logic in a
 *    testable class rather than an opaque SpEL string.
 *
 * 2. {@code /api/subscriptions/**} PUT/DELETE — requires the {@code FACTOR_TOTP}
 *    authority, modelling a step-up authentication requirement for billing mutations.
 *
 * {@code PathPatternRequestMatcher} is the Spring Security 7 replacement for the
 * deprecated {@code AntPathRequestMatcher}. It uses the same path-pattern syntax
 * as Spring MVC, so URL matching is consistent across the framework.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final SubscriptionTierAuthorizationManager subscriptionTierAuthorizationManager;

    public SecurityConfig(SubscriptionTierAuthorizationManager subscriptionTierAuthorizationManager) {
        this.subscriptionTierAuthorizationManager = subscriptionTierAuthorizationManager;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                // Catalog: delegate to custom AuthorizationManager
                .requestMatchers(
                        PathPatternRequestMatcher.pathPattern(HttpMethod.GET, "/api/catalog/**"))
                    .access(subscriptionTierAuthorizationManager)
                // Subscription mutations: require TOTP step-up
                .requestMatchers(
                        PathPatternRequestMatcher.pathPattern(HttpMethod.PUT,    "/api/subscriptions/**"),
                        PathPatternRequestMatcher.pathPattern(HttpMethod.DELETE, "/api/subscriptions/**"))
                    .hasAuthority("FACTOR_TOTP")
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
                .authorities("ROLE_USER", "TIER_PREMIUM")
                .build();

        var bob = User.withDefaultPasswordEncoder()
                .username("bob")
                .password("password")
                .authorities("ROLE_USER", "TIER_BASIC")
                .build();

        return new InMemoryUserDetailsManager(alice, bob);
    }
}
