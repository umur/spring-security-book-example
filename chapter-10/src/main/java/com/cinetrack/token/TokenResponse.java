package com.cinetrack.token;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * OAuth2-style token response body.
 */
public record TokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") long expiresIn,
        String scope
) {
}
