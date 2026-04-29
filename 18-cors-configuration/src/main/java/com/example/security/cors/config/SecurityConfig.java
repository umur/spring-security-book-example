package com.example.security.cors.config;

import com.example.security.cors.repository.AppUserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Allowed origins for the restricted /api/data endpoint.
     * Any other origin will not receive CORS headers for that path.
     */
    public static final String TRUSTED_ORIGIN = "https://trusted.example.com";
    public static final String ANOTHER_TRUSTED_ORIGIN = "https://app.example.com";

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/public").permitAll()
                        .requestMatchers("/api/data").authenticated()
                        .anyRequest().authenticated()
                )
                .httpBasic(basic -> {})
                .build();
    }

    /**
     * Defines per-path CORS policies:
     * <ul>
     *   <li>/api/public — any origin, GET only, no credentials</li>
     *   <li>/api/data   — restricted to trusted origins, GET + POST,
     *                     specific request headers, credentials allowed</li>
     * </ul>
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        // Public endpoint: open CORS — any origin may call GET
        CorsConfiguration publicConfig = new CorsConfiguration();
        publicConfig.setAllowedOriginPatterns(List.of("*"));
        publicConfig.setAllowedMethods(List.of("GET", "OPTIONS"));
        publicConfig.setAllowedHeaders(List.of("*"));
        publicConfig.setAllowCredentials(false);
        publicConfig.setMaxAge(3600L);
        source.registerCorsConfiguration("/api/public", publicConfig);

        // Restricted endpoint: specific trusted origins only
        CorsConfiguration restrictedConfig = new CorsConfiguration();
        restrictedConfig.setAllowedOrigins(List.of(TRUSTED_ORIGIN, ANOTHER_TRUSTED_ORIGIN));
        restrictedConfig.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        restrictedConfig.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
        restrictedConfig.setExposedHeaders(List.of("X-Total-Count"));
        restrictedConfig.setAllowCredentials(true);
        restrictedConfig.setMaxAge(1800L);
        source.registerCorsConfiguration("/api/data", restrictedConfig);

        return source;
    }

    @Bean
    UserDetailsService userDetailsService(AppUserRepository userRepository) {
        return username -> userRepository.findByUsername(username)
                .map(user -> new User(
                        user.getUsername(),
                        user.getPassword(),
                        user.isEnabled(), true, true, true,
                        List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole()))
                ))
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
