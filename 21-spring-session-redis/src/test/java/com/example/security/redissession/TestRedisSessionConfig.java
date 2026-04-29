package com.example.security.redissession;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.FlushMode;
import org.springframework.session.config.SessionRepositoryCustomizer;
import org.springframework.session.data.redis.RedisSessionRepository;

@TestConfiguration
public class TestRedisSessionConfig {

    /**
     * Forces IMMEDIATE flush mode so sessions are written to Redis synchronously
     * within the same request, making them visible to assertions in the same test.
     */
    @Bean
    SessionRepositoryCustomizer<RedisSessionRepository> immediateFlushCustomizer() {
        return repo -> repo.setFlushMode(FlushMode.IMMEDIATE);
    }

    /**
     * Test-only SecurityFilterChain with CSRF disabled so integration tests can POST
     * to /login without managing CSRF tokens. Because SecurityConfig.filterChain is
     * annotated with @ConditionalOnMissingBean(SecurityFilterChain.class), this bean
     * is registered first (via @Import) and the production one is skipped entirely.
     */
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/css/**", "/error").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/dashboard", true)
                        .failureUrl("/login?error")
                )
                .httpBasic(basic -> {})
                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("SESSION")
                )
                .sessionManagement(session -> session
                        .sessionFixation().changeSessionId()
                )
                .build();
    }
}
