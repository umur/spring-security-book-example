package com.example.security.filterchain.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Adds an {@code X-Rate-Limit-Remaining} header to every response.
 * For demonstration purposes the counter is a simple in-memory decrementing value.
 */
public class RateLimitHeaderFilter extends OncePerRequestFilter {

    public static final String HEADER_NAME = "X-Rate-Limit-Remaining";
    private static final int MAX_REQUESTS = 1000;

    private final AtomicInteger remaining = new AtomicInteger(MAX_REQUESTS);

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        int current = remaining.updateAndGet(v -> v > 0 ? v - 1 : 0);
        response.setHeader(HEADER_NAME, String.valueOf(current));

        filterChain.doFilter(request, response);
    }
}
