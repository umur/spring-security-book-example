package com.cinetrack.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import java.security.interfaces.RSAPublicKey;

/**
 * Security configuration for the catalog-service role in the zero-trust mesh.
 *
 * Key decisions:
 * <ul>
 *   <li>Stateless — no HTTP session, no CSRF risk from cookies.</li>
 *   <li>Audience-validated JWT — only tokens minted for {@code catalog-service}
 *       are accepted. A stolen token from {@code subscription-service} is
 *       rejected at the validator level before any business logic runs.</li>
 *   <li>Every path under {@code /api/catalog/**} requires authentication.
 *       There is no permit-all escape hatch for machine-to-machine APIs.</li>
 * </ul>
 *
 * The wiring delegates to {@link AudienceValidator} for the audience check
 * and wraps the default Spring Security validators so expiry is still enforced.
 */
@Configuration
@EnableWebSecurity
public class ServiceSecurityConfig {

    static final String REQUIRED_AUDIENCE = "catalog-service";

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtDecoder audienceAwareDecoder) throws Exception {
        http
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/catalog/**").authenticated()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.decoder(audienceAwareDecoder))
            );

        return http.build();
    }

    /**
     * Overrides the default decoder to layer in audience validation.
     *
     * The delegate chain: expiry check (createDefault) + audience check (ours).
     * No issuer validator — this demo uses a locally-generated RSA key pair with
     * no issuer URI. In production, replace createDefault() with
     * JwtValidators.createDefaultWithIssuer(issuerUri) so the iss claim is also
     * validated.
     */
    @Bean
    public JwtDecoder audienceAwareDecoder(JwkConfig jwkConfig) throws Exception {
        RSAPublicKey publicKey = jwkConfig.rsaKey().toRSAPublicKey();
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey).build();

        AudienceValidator audienceValidator = new AudienceValidator(REQUIRED_AUDIENCE);
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
            JwtValidators.createDefault(),
            audienceValidator
        ));
        return decoder;
    }
}
