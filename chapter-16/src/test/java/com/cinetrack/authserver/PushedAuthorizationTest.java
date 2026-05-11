package com.cinetrack.authserver;

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

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Chapter 16: Integration tests for the Pushed Authorization Request (PAR) flow.
 *
 * PAR (RFC 9126) lets a client submit all authorization parameters server-side
 * before redirecting the user. The server returns a "request_uri" — an opaque,
 * short-lived reference the client includes in the redirect instead of the
 * full parameter set. This prevents parameter tampering and keeps sensitive
 * parameters out of browser history and server logs.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
class PushedAuthorizationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    /**
     * A valid PAR request from cinetrack-web must return a request_uri and
     * an expires_in value so the client knows how long the reference is valid.
     */
    @Test
    void pushedAuthorizationRequest_withValidClient_returnsRequestUri() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", "cinetrack-web");
        body.add("client_secret", "web-secret");
        body.add("response_type", "code");
        body.add("scope", "openid catalog:read");
        body.add("redirect_uri", "http://localhost:3000/callback");
        body.add("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        body.add("code_challenge_method", "S256");

        ResponseEntity<Map> response = restTemplate.postForEntity(
                "http://localhost:" + port + "/oauth2/par",
                new HttpEntity<>(body, headers),
                Map.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).containsKey("request_uri");
        assertThat(response.getBody()).containsKey("expires_in");

        String requestUri = (String) response.getBody().get("request_uri");
        assertThat(requestUri).startsWith("urn:ietf:params:oauth:request_uri:");
    }
}
