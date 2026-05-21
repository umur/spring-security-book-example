package com.cinetrack.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.server.ServerWebExchange;

/**
 * Reactive resource server that accepts tokens from multiple issuers.
 *
 * Instead of wiring a single {@link org.springframework.security.oauth2.jwt.ReactiveJwtDecoder},
 * we inject a {@link ReactiveAuthenticationManagerResolver} that selects the
 * correct decoder based on the {@code iss} claim in the incoming token.
 *
 * This pattern is required when a single service trusts tokens from more than
 * one authorization server: for example when CineTrack federates both its
 * own auth server and a partner IdP.
 *
 * Stateless behaviour is configured via
 * {@link NoOpServerSecurityContextRepository}: the reactive stack does not
 * have a {@code SessionCreationPolicy.STATELESS} equivalent.
 *
 * Method security ({@code @PreAuthorize}) is enabled via
 * {@link EnableReactiveMethodSecurity} so that fine-grained scope checks can
 * live on the controller methods rather than in this configuration class.
 */
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class ReactiveResourceServerConfig {

    private final ReactiveAuthenticationManagerResolver<ServerWebExchange> authManagerResolver;

    public ReactiveResourceServerConfig(
            ReactiveAuthenticationManagerResolver<ServerWebExchange> authManagerResolver) {
        this.authManagerResolver = authManagerResolver;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .authorizeExchange(auth -> auth
                .pathMatchers("/api/recommendations/**").authenticated()
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .authenticationManagerResolver(authManagerResolver)
            );

        return http.build();
    }
}
