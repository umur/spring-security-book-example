package com.example.security.mfa.security;

import com.example.security.mfa.service.AuthService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Reads the X-Session-Token header and sets a fully-authenticated SecurityContext.
 */
@RequiredArgsConstructor
public class SessionTokenFilter extends OncePerRequestFilter {

    public static final String SESSION_TOKEN_HEADER = "X-Session-Token";

    private final AuthService authService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String token = request.getHeader(SESSION_TOKEN_HEADER);
        if (token != null && !token.isBlank()) {
            Authentication auth = authService.resolveSession(token);
            if (auth != null) {
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }

        filterChain.doFilter(request, response);
    }
}
