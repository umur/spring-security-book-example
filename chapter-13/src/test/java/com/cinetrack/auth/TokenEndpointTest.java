package com.cinetrack.auth;

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

import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Chapter 13: Integration tests for the token and discovery endpoints.
 *
 * Uses a real HTTP server (RANDOM_PORT) because the authorization server
 * endpoints are registered by the framework outside the MockMvc servlet context.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
class TokenEndpointTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    /**
     * catalog-service authenticates with client_credentials.
     * A valid response must contain an access_token and token_type=Bearer.
     */
    @Test
    void clientCredentials_withValidClient_returnsAccessToken() {
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
        assertThat(response.getBody()).containsKey("access_token");
        assertThat(response.getBody().get("token_type")).isEqualTo("Bearer");
    }

    /**
     * The JWKS endpoint must be publicly accessible and return a valid key set.
     * Clients use this to verify JWT signatures without contacting the IdP for every request.
     */
    @Test
    void jwksEndpoint_returns200WithKeys() {
        ResponseEntity<Map> response = restTemplate.getForEntity(
                "http://localhost:" + port + "/oauth2/jwks",
                Map.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsKey("keys");
    }

    /**
     * The OIDC discovery document tells clients where every endpoint lives.
     * Issuer must exactly match the value configured in AuthorizationServerSettings.
     */
    @Test
    void oidcDiscovery_returns200WithCorrectIssuer() {
        ResponseEntity<Map> response = restTemplate.getForEntity(
                "http://localhost:" + port + "/.well-known/openid-configuration",
                Map.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().get("issuer")).isEqualTo("http://localhost:8080");
    }

    private static String basicAuth(String clientId, String clientSecret) {
        String credentials = clientId + ":" + clientSecret;
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes());
    }
}
