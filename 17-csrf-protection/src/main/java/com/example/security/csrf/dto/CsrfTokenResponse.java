package com.example.security.csrf.dto;

public record CsrfTokenResponse(
        String headerName,
        String parameterName,
        String token
) {
}
