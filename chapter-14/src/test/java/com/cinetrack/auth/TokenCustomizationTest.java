package com.cinetrack.auth;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Chapter 14: Integration tests for token customization.
 *
 * Fetches real JWTs from the running authorization server and parses
 * the claim set to verify that customization rules were applied correctly.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
class TokenCustomizationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    /**
     * Service tokens issued via client_credentials carry no user context.
     * The customizer must leave them clean: no "tier" claim should appear.
     */
    @Test
    void clientCredentialsToken_doesNotContainTierClaim() throws Exception {
        String token = fetchClientCredentialsToken();
        JWTClaimsSet claims = SignedJWT.parse(token).getJWTClaimsSet();

        assertThat(claims.getClaim("tier")).isNull();
    }

    /**
     * The access token TTL is configured to 15 minutes.
     * We verify it is within a 1-minute tolerance to guard against clock skew
     * in the test environment without being brittle.
     */
    @Test
    void accessToken_ttlIsApproximately15Minutes() throws Exception {
        String token = fetchClientCredentialsToken();
        JWTClaimsSet claims = SignedJWT.parse(token).getJWTClaimsSet();

        Date issuedAt = claims.getIssueTime();
        Date expiresAt = claims.getExpirationTime();

        assertThat(issuedAt).isNotNull();
        assertThat(expiresAt).isNotNull();

        Duration actualTtl = Duration.between(issuedAt.toInstant(), expiresAt.toInstant());
        assertThat(actualTtl).isBetween(Duration.ofMinutes(14), Duration.ofMinutes(16));
    }

    // -------------------------------------------------------------------------

    private String fetchClientCredentialsToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set(HttpHeaders.AUTHORIZATION, basicAuth("catalog-service", "secret"));

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "client_credentials");
        body.add("scope", "catalog.internal");

        ResponseEntity<Map> response = restTemplate.postForEntity(
                "http://localhost:" + port + "/oauth2/token",
                new HttpEntity<>(body, headers),
                Map.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        return (String) response.getBody().get("access_token");
    }

    private static String basicAuth(String clientId, String clientSecret) {
        String credentials = clientId + ":" + clientSecret;
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes());
    }
}
