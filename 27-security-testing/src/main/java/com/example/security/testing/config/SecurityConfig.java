package com.example.security.testing.config;

import com.example.security.testing.repository.AppUserRepository;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Security configuration for the security-testing reference module.
 *
 * Deliberately supports multiple authentication mechanisms so that every
 * testing pattern — form login, HTTP Basic, JWT bearer token — can be
 * demonstrated in a single application:
 *
 *   - Form login:   used by TestRestTemplate integration tests
 *   - HTTP Basic:   used by MockMvc .with(httpBasic(...)) tests
 *   - JWT bearer:   used by MockMvc .with(jwt()) post-processor tests
 *   - CSRF:         enabled for mutating endpoints (POST /api/data)
 *   - CORS:         configured for /api/** to demonstrate CORS testing
 *   - Method security: @PreAuthorize annotations enforced on the service layer
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    /** Symmetric key used for signing JWTs in tests (HS256). */
    public static final String JWT_SECRET =
            "test-secret-key-at-least-32-bytes-long-for-hs256";

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/public", "/login", "/error").permitAll()
                        .requestMatchers("/api/admin").hasRole("ADMIN")
                        .requestMatchers("/api/user", "/api/data").authenticated()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/api/user", true)
                        .failureUrl("/login?error")
                        .permitAll()
                )
                .httpBasic(basic -> {})
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.decoder(jwtDecoder()))
                        .authenticationEntryPoint((req, res, ex) ->
                                res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"))
                )
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // CSRF enabled — tests demonstrate both with(csrf()) and without
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/api/public")
                )
                .sessionManagement(session -> session
                        .maximumSessions(1)
                )
                .headers(headers -> headers
                        .frameOptions(frame -> frame.deny())
                        .contentTypeOptions(ct -> {})
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31536000)
                                // Send HSTS over plain HTTP as well so MockMvc tests can verify it.
                                // In production, restrict to HTTPS only (the default).
                                .requestMatcher(request -> true)
                        )
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'")
                        )
                        .referrerPolicy(rp -> rp
                                .policy(org.springframework.security.web.header.writers
                                        .ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                        )
                        .permissionsPolicy(pp -> pp
                                .policy("camera=(), microphone=(), geolocation=()")
                        )
                )
                .build();
    }

    @Bean
    UserDetailsService userDetailsService(AppUserRepository repo) {
        return username -> repo.findByUsername(username)
                .map(u -> new User(
                        u.getUsername(),
                        u.getPassword(),
                        u.isEnabled(), true, true, true,
                        List.of(new SimpleGrantedAuthority("ROLE_" + u.getRole()))
                ))
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    DaoAuthenticationProvider authenticationProvider(UserDetailsService uds,
                                                     PasswordEncoder encoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(uds);
        provider.setPasswordEncoder(encoder);
        return provider;
    }

    /**
     * HS256 JWT decoder used for the OAuth2 resource server filter.
     * In tests the .with(jwt()) post-processor bypasses this decoder entirely,
     * injecting a pre-built JwtAuthenticationToken directly into the SecurityContext.
     */
    @Bean
    JwtDecoder jwtDecoder() {
        byte[] keyBytes = JWT_SECRET.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "HmacSHA256");
        return NimbusJwtDecoder.withSecretKey(key).build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("https://trusted.example.com"));
        config.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }
}
