package com.example.security.saml2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security configuration for SAML 2.0 SSO login.
 *
 * Key concepts demonstrated:
 * - saml2Login() activates the SAML 2.0 authentication filter chain
 * - The relying party (SP) registration is loaded from application.yml
 * - /saml2/metadata is the auto-generated SP metadata endpoint (Spring Security serves it)
 * - saml2Logout() enables SLO (Single Logout) support
 *
 * In production, the IdP metadata URL would point to a real identity provider.
 * For this demo a mock IdP registration is configured in application.yml using
 * a self-signed certificate so the SP metadata endpoint and redirect flows can
 * be exercised without a live IdP.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
                        // SP metadata must be public — IdPs fetch it before any user session
                        .requestMatchers("/saml2/metadata/**", "/error").permitAll()
                        .anyRequest().authenticated()
                )
                .saml2Login(saml2 -> saml2
                        // Default login page provided by Spring Security at /login
                        .loginPage("/login")
                        .defaultSuccessUrl("/dashboard", true)
                )
                .saml2Metadata(saml2 -> {})
                .build();
    }
}
