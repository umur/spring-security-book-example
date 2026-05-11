package com.cinetrack.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Primary security configuration for the OIDC social-login flow.
 *
 * All requests to /api/users/** require an authenticated OIDC session.
 * The login and root paths are open so the IdP redirect can complete.
 * CineTrackOidcUserService intercepts the UserInfo response and can
 * enrich or persist the principal before it enters the SecurityContext.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CineTrackOidcUserService cineTrackOidcUserService;

    public SecurityConfig(CineTrackOidcUserService cineTrackOidcUserService) {
        this.cineTrackOidcUserService = cineTrackOidcUserService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/").permitAll()
                .requestMatchers("/api/users/**").authenticated()
                .anyRequest().authenticated()
            )
            .oauth2Login(login -> login
                .userInfoEndpoint(info ->
                    info.oidcUserService(cineTrackOidcUserService)
                )
            )
            .logout(Customizer.withDefaults());

        return http.build();
    }
}
