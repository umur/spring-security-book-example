package com.cinetrack.firewall;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that StrictHttpFirewall rejects malicious URL patterns before they
 * reach any controller.
 *
 * Path traversal attacks attempt to escape the intended URL space by inserting
 * {@code ..} segments. Spring Security's StrictHttpFirewall detects and blocks
 * these sequences at the filter chain level and throws RequestRejectedException.
 *
 * Spring Boot's error handling then processes the rejected request via the
 * /error endpoint. Because the application is stateless (STATELESS session
 * policy), that secondary /error request arrives without credentials and
 * receives 401. The important assertion is that the original path never
 * reached a controller -- the status is 4xx, not 200.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class HttpFirewallTest {

    @LocalServerPort
    int port;

    RestClient client;

    @BeforeEach
    void setUp() {
        String credentials = Base64.getEncoder().encodeToString("alice:password".getBytes());
        client = RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultHeader("Authorization", "Basic " + credentials)
                .build();
    }

    @Test
    void pathTraversal_isRejected() {
        // The firewall blocks /../ at the filter chain level (RequestRejectedException).
        // Spring Boot's error controller then handles the rejection. Because the
        // error endpoint also requires authentication and the stateless session
        // means no session is available, the final HTTP status is 400 or 401 --
        // either way the traversal path never reached a controller.
        ResponseEntity<Void> response = client.get()
                .uri("/api/../secret")
                .retrieve()
                .onStatus(status -> status.is4xxClientError(), (req, res) -> {})
                .toBodilessEntity();

        int status = response.getStatusCode().value();
        assertThat(status)
                .as("Firewall must reject the path-traversal attempt with a 4xx status")
                .isBetween(400, 499);
    }
}
