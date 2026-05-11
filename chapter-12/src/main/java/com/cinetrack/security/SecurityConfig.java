package com.cinetrack.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * OAuth2 client security configuration for recommendation-service.
 *
 * This service plays two roles simultaneously:
 *
 *   1. As a web application serving end-users — uses OAuth2 login (authorization
 *      code flow) so users authenticate via the authorization server rather than
 *      submitting credentials directly to this service.
 *
 *   2. As a service-to-service client — uses client credentials to obtain tokens
 *      when calling catalog-service's API. The WebClient handles this transparently
 *      via ServletOAuth2AuthorizedClientExchangeFilterFunction.
 *
 * Sessions are stateful here because the OAuth2 login flow requires storing the
 * authorization code state between the redirect to the AS and the callback.
 * Service-to-service calls use their own token lifecycle managed by
 * OAuth2AuthorizedClientManager.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/oauth2/**", "/error").permitAll()
                .requestMatchers("/api/recommendations/**").authenticated()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .defaultSuccessUrl("/api/recommendations", true)
            );

        return http.build();
    }
}
