package com.cinetrack.authserver;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Chapter 16: Verifies that the OIDC discovery document advertises
 * both the Device Authorization endpoint and the PAR endpoint.
 *
 * Clients and libraries consume the discovery document at startup to locate
 * all endpoints. If an endpoint is missing here, clients will not know it
 * exists even if the server supports it.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
class DiscoveryTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    /**
     * The discovery document must contain "device_authorization_endpoint"
     * so RFC 8628-compliant clients can find the endpoint automatically.
     */
    @Test
    void discoveryDocument_containsDeviceAuthorizationEndpoint() {
        ResponseEntity<Map> response = restTemplate.getForEntity(
                "http://localhost:" + port + "/.well-known/openid-configuration",
                Map.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsKey("device_authorization_endpoint");
    }

    /**
     * The discovery document must contain "pushed_authorization_request_endpoint"
     * so RFC 9126-compliant clients can find the PAR endpoint automatically.
     */
    @Test
    void discoveryDocument_containsPushedAuthorizationRequestEndpoint() {
        ResponseEntity<Map> response = restTemplate.getForEntity(
                "http://localhost:" + port + "/.well-known/openid-configuration",
                Map.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsKey("pushed_authorization_request_endpoint");
    }
}
