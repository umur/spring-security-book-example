package com.cinetrack;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * Security configuration for Chapter 4: Session Management and CSRF.
 *
 * Key decisions:
 * - Session creation policy is IF_REQUIRED (default) so the application
 *   participates in normal browser session management.
 * - Concurrent sessions are capped at 2; exceeding the cap expires the
 *   oldest session rather than preventing new logins.
 * - Session fixation protection uses changeSessionId(), which retains
 *   attributes while rotating the identifier on authentication.
 * - CSRF uses CookieCsrfTokenRepository with httpOnly=false so that
 *   JavaScript clients (e.g., a React SPA) can read the token from the
 *   XSRF-TOKEN cookie and echo it back in the X-XSRF-TOKEN header.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/logout").permitAll()
                .requestMatchers("/api/movies/**").authenticated()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginProcessingUrl("/login")
                .successHandler(jsonSuccessHandler())
                .failureHandler(jsonFailureHandler())
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .sessionFixation(fixation -> fixation.changeSessionId())
                .maximumSessions(2)
                    .maxSessionsPreventsLogin(false)
            )
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            );

        return http.build();
    }

    /**
     * Publishes HttpSessionDestroyedEvent so that Spring Security's concurrent
     * session control can invalidate the oldest session when the cap is reached.
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        var alice = User.withDefaultPasswordEncoder()
                .username("alice")
                .password("password")
                .roles("USER")
                .build();

        var bob = User.withDefaultPasswordEncoder()
                .username("bob")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(alice, bob);
    }

    // -----------------------------------------------------------------------
    // Handlers that return JSON instead of redirecting, suitable for SPAs.
    // Written without ObjectMapper to avoid pulling Jackson into the config
    // class directly; the response bodies are simple enough to hand-write.
    // -----------------------------------------------------------------------

    private AuthenticationSuccessHandler jsonSuccessHandler() {
        return (HttpServletRequest request, HttpServletResponse response, Authentication authentication)
                -> writeJson(response, HttpServletResponse.SC_OK,
                        "{\"username\":\"" + authentication.getName() + "\",\"authenticated\":true}");
    }

    private AuthenticationFailureHandler jsonFailureHandler() {
        return (HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
                -> writeJson(response, HttpServletResponse.SC_UNAUTHORIZED,
                        "{\"error\":\"Bad credentials\",\"authenticated\":false}");
    }

    private void writeJson(HttpServletResponse response, int status, String body) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(status);
        PrintWriter writer = response.getWriter();
        writer.write(body);
        writer.flush();
    }
}
