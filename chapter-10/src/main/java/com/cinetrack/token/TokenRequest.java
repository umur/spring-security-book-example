package com.cinetrack.token;

/**
 * Request body for the demo token endpoints.
 */
public record TokenRequest(String clientId, String scope) {
}
