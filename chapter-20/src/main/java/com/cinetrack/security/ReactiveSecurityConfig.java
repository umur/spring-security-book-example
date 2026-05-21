package com.cinetrack.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

/**
 * Reactive security configuration for the WebFlux stack.
 *
 * The servlet-world {@code HttpSecurity} and {@code SecurityFilterChain} are
 * replaced by {@link ServerHttpSecurity} and {@link SecurityWebFilterChain}.
 * Every operation on the filter chain is non-blocking: authentication,
 * authorization decisions, and JWT decoding all return {@code Mono} internally.
 *
 * Key differences from the servlet model:
 * <ul>
 *   <li>{@code authorizeExchange} replaces {@code authorizeHttpRequests}.</li>
 *   <li>Stateless behaviour is configured via {@code securityContextRepository(NoOpServerSecurityContextRepository)}
 *       rather than a session-creation policy: the reactive stack has no
 *       equivalent of {@code SessionCreationPolicy.STATELESS}.</li>
 *   <li>The JWT decoder must be a {@link ReactiveJwtDecoder}, not a blocking {@code JwtDecoder}.</li>
 * </ul>
 */
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class ReactiveSecurityConfig {

    private final ReactiveJwtDecoder reactiveJwtDecoder;

    public ReactiveSecurityConfig(ReactiveJwtDecoder reactiveJwtDecoder) {
        this.reactiveJwtDecoder = reactiveJwtDecoder;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
            // NoOpServerSecurityContextRepository is the reactive equivalent of
            // SessionCreationPolicy.STATELESS: it discards the security context
            // after each request instead of storing it in a web session.
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .authorizeExchange(auth -> auth
                .pathMatchers("/api/catalog/**").hasAuthority("SCOPE_catalog:read")
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtDecoder(reactiveJwtDecoder))
            );

        return http.build();
    }
}
