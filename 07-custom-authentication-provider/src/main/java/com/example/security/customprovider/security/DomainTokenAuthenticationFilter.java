package com.example.security.customprovider.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filter that extracts the {@code X-Domain-Token} header from each request
 * and attempts authentication via the {@link AuthenticationManager}.
 *
 * If the header is absent the filter passes through without touching the
 * SecurityContext, allowing other authentication mechanisms (e.g. HTTP Basic)
 * to run.
 */
@Slf4j
@RequiredArgsConstructor
public class DomainTokenAuthenticationFilter extends OncePerRequestFilter {

    public static final String DOMAIN_TOKEN_HEADER = "X-Domain-Token";

    private final AuthenticationManager authenticationManager;
    private final SecurityContextHolderStrategy securityContextHolderStrategy =
            SecurityContextHolder.getContextHolderStrategy();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String token = request.getHeader(DOMAIN_TOKEN_HEADER);

        if (token == null || token.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("Found X-Domain-Token header, attempting token authentication");

        try {
            Authentication authRequest = new DomainTokenAuthenticationToken(token);
            Authentication authResult = authenticationManager.authenticate(authRequest);

            var context = securityContextHolderStrategy.createEmptyContext();
            context.setAuthentication(authResult);
            securityContextHolderStrategy.setContext(context);

            log.debug("Domain token authentication set in SecurityContext for user '{}'",
                    authResult.getName());
        } catch (AuthenticationException ex) {
            securityContextHolderStrategy.clearContext();
            log.debug("Domain token authentication failed: {}", ex.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}
