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

import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Chapter 16: Integration tests for the Device Authorization Grant flow.
 *
 * The Device Authorization Grant is a two-step flow:
 *   1. The device posts to /oauth2/device_authorization to obtain a device_code,
 *      user_code, and verification_uri.
 *   2. The user visits the verification_uri on another device, enters the user_code,
 *      and approves. The device polls /oauth2/token until it gets an access token.
 *
 * These tests cover step 1 and the accessibility of the verification page.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
class DeviceAuthorizationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    /**
     * The device authorization endpoint must return the three values the TV app
     * needs to show the user: a device_code (for polling), a user_code (for the
     * user to type), and a verification_uri (where to type it).
     */
    @Test
    void deviceAuthorizationRequest_withValidClient_returnsDeviceAndUserCode() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set(HttpHeaders.AUTHORIZATION, basicAuth("cinetrack-tv", "tv-secret"));

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", "cinetrack-tv");
        body.add("scope", "catalog:read");

        ResponseEntity<Map> response = restTemplate.postForEntity(
                "http://localhost:" + port + "/oauth2/device_authorization",
                new HttpEntity<>(body, headers),
                Map.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsKey("device_code");
        assertThat(response.getBody()).containsKey("user_code");
        assertThat(response.getBody()).containsKey("verification_uri");
    }

    /**
     * The verification page (/activate) must be accessible without authentication.
     * The user lands here from the TV screen without any prior session.
     */
    @Test
    void activatePage_isAccessibleWithoutAuthentication() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "http://localhost:" + port + "/activate",
                String.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    private static String basicAuth(String clientId, String clientSecret) {
        String credentials = clientId + ":" + clientSecret;
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes());
    }
}
