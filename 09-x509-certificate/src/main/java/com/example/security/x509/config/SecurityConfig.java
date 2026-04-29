package com.example.security.x509.config;

import com.example.security.x509.service.CertificateUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import java.time.Instant;

/**
 * Security configuration for X.509 mutual TLS client certificate authentication.
 *
 * Key design decisions:
 * - {@code x509()} instructs Spring Security to look for a client certificate
 *   on every request (populated by the servlet container / TLS terminator).
 * - {@code SubjectDnX509PrincipalExtractor} extracts the CN from the certificate
 *   subject and passes it to {@link CertificateUserService} to load authorities.
 * - Sessions are stateless; CSRF is disabled (API-only, machine-to-machine).
 *
 * Running with real mTLS:
 *   Start with {@code server.ssl.client-auth=need} and supply a keystore/truststore.
 *   See README for keytool commands to generate self-signed certificates.
 *
 * Running in tests:
 *   MockMvc's {@code SecurityMockMvcRequestPostProcessors.x509(certificate)}
 *   post-processor injects a pre-built {@code X509Certificate} into the request
 *   attributes so the X.509 filter can authenticate without actual TLS.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CertificateUserService certificateUserService;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .x509(x509 -> x509
                        .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                        .userDetailsService(certificateUserService)
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/api/admin").hasRole("ADMIN")
                        .requestMatchers("/api/profile").authenticated()
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
                                    "{\"error\":\"Unauthorized\",\"message\":\"Valid client certificate required\",\"timestamp\":\"" + Instant.now() + "\"}"
                            );
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setStatus(HttpStatus.FORBIDDEN.value());
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            response.getWriter().write(
                                    "{\"error\":\"Forbidden\",\"message\":\"Insufficient certificate privileges\",\"timestamp\":\"" + Instant.now() + "\"}"
                            );
                        })
                )
                .build();
    }
}
