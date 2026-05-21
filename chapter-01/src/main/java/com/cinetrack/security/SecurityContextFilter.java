package com.cinetrack.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Logs the concrete Authentication type on every request into MDC.
 *
 * This makes the SecurityContext lifecycle visible in logs: useful for
 * understanding how Spring Security populates and clears the context
 * across the filter chain.
 */
@Component
public class SecurityContextFilter extends OncePerRequestFilter {

    private static final String MDC_KEY = "auth.type";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String authType = (authentication != null)
                ? authentication.getClass().getSimpleName()
                : "none";

        MDC.put(MDC_KEY, authType);
        try {
            filterChain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_KEY);
        }
    }
}
