package com.cinetrack;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

/**
 * Security configuration for Chapter 5: HTTP Hardening.
 *
 * Key decisions:
 * - Session policy is STATELESS; every request must carry HTTP Basic
 *   credentials. No session cookies are issued.
 * - CSRF is disabled because CSRF attacks exploit the browser's automatic
 *   attachment of session cookies; with no cookies there is nothing to forge.
 * - Security headers are set explicitly rather than relying on defaults, so
 *   the configuration doubles as documentation for what each header does.
 * - HSTS requestMatcher is set to AnyRequestMatcher so the header is emitted
 *   over plain HTTP as well, which makes it testable in integration tests that
 *   use an embedded Tomcat without TLS. In production, restrict this to HTTPS.
 * - StrictHttpFirewall rejects path traversal sequences and double-encoded
 *   slashes before requests ever reach a controller.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/**").authenticated()
                .anyRequest().authenticated()
            )
            .httpBasic(Customizer.withDefaults())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .csrf(csrf -> csrf.disable())
            .headers(headers -> headers
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                .contentTypeOptions(Customizer.withDefaults())
                .httpStrictTransportSecurity(hsts -> hsts
                    .requestMatcher(AnyRequestMatcher.INSTANCE)
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000)
                )
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'self'; script-src 'self'")
                )
            );

        return http.build();
    }

    /**
     * Replaces the default firewall with a strict variant that rejects:
     * - Path traversal sequences (/../)
     * - Double-encoded slashes (%2F)
     * - Semicolon path parameters
     */
    @Bean
    public HttpFirewall strictHttpFirewall() {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
        firewall.setAllowUrlEncodedSlash(false);
        firewall.setAllowSemicolon(false);
        firewall.setAllowBackSlash(false);
        firewall.setAllowUrlEncodedDoubleSlash(false);
        return firewall;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        var alice = User.withDefaultPasswordEncoder()
                .username("alice")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(alice);
    }
}
