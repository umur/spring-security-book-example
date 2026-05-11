package com.cinetrack;

import com.cinetrack.mfa.MfaUserDetailsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * Security configuration for Chapter 6: Multi-Factor Authentication.
 *
 * Authority model:
 * - FACTOR_PASSWORD  -- granted immediately on successful username/password login.
 * - FACTOR_TOTP      -- granted only after the user submits a valid TOTP code
 *                       via POST /api/mfa/verify.
 *
 * Endpoint protection:
 * - /api/movies/**              requires FACTOR_PASSWORD only.
 * - /api/subscriptions/upgrade  requires FACTOR_TOTP (implies password was also done).
 * - /api/mfa/**                 requires authentication (FACTOR_PASSWORD at minimum).
 *
 * The success handler adds FACTOR_PASSWORD to the authentication immediately
 * after login. If the user also has a TOTP secret configured, the handler
 * signals to the client that a second factor is required by returning a JSON
 * body with mfaRequired=true instead of the usual success response.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final MfaUserDetailsService mfaUserDetailsService;

    public SecurityConfig(MfaUserDetailsService mfaUserDetailsService) {
        this.mfaUserDetailsService = mfaUserDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/logout").permitAll()
                .requestMatchers("/api/subscriptions/upgrade").hasAuthority("FACTOR_TOTP")
                .requestMatchers("/api/movies/**").hasAuthority("FACTOR_PASSWORD")
                .requestMatchers("/api/mfa/**").authenticated()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginProcessingUrl("/login")
                .successHandler(mfaAwareSuccessHandler())
                .failureHandler(jsonFailureHandler())
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            .csrf(csrf -> csrf.disable()); // disabled for demo simplicity; re-enable in production

        return http.build();
    }

    /**
     * On successful password authentication, grants FACTOR_PASSWORD and
     * persists the enriched authentication to the session. If the user has a
     * TOTP secret, the response signals that a second factor is required.
     */
    private AuthenticationSuccessHandler mfaAwareSuccessHandler() {
        return (HttpServletRequest request, HttpServletResponse response, Authentication authentication) -> {
            // Add FACTOR_PASSWORD to the authenticated principal.
            List<GrantedAuthority> authorities = new ArrayList<>(authentication.getAuthorities());
            authorities.add(new SimpleGrantedAuthority("FACTOR_PASSWORD"));

            Authentication enriched = UsernamePasswordAuthenticationToken.authenticated(
                    authentication.getPrincipal(),
                    authentication.getCredentials(),
                    authorities
            );

            SecurityContext context = SecurityContextHolder.getContext();
            context.setAuthentication(enriched);

            // Persist to session.
            HttpSession session = request.getSession(true);
            session.setAttribute(
                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                    context
            );

            // Determine whether a second factor is required.
            boolean hasTotpSecret = mfaUserDetailsService.findMfaUser(authentication.getName())
                    .totpSecret() != null;

            String body = "{\"username\":\"" + authentication.getName()
                    + "\",\"authenticated\":true,\"mfaRequired\":" + hasTotpSecret + "}";
            writeJson(response, HttpServletResponse.SC_OK, body);
        };
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
