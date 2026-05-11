package com.cinetrack.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests that verify SecurityContext population end-to-end.
 *
 * The filter chain runs for real here — no mocking — so we can assert
 * on the actual HTTP responses that result from context state.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class SecurityContextPropagationTest {

    @LocalServerPort
    int port;

    RestClient client;

    @BeforeEach
    void setUp() {
        client = RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .build();
    }

    @Test
    void anonymousRequest_isRejectedWith401() {
        // Anonymous requests carry an AnonymousAuthenticationToken internally,
        // but the filter chain rejects them before the controller is reached.
        ResponseEntity<Void> response = client.get()
                .uri("/api/movies")
                .retrieve()
                .onStatus(status -> status.value() == 401, (req, res) -> {})
                .toBodilessEntity();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void authenticatedRequest_reachesControllerWith200() {
        // A valid Basic credential causes Spring Security to populate a
        // UsernamePasswordAuthenticationToken in the SecurityContext.
        ResponseEntity<Void> response = client.get()
                .uri("/api/movies")
                .headers(headers -> headers.setBasicAuth("user", "password"))
                .retrieve()
                .onStatus(status -> !status.is2xxSuccessful(), (req, res) -> {})
                .toBodilessEntity();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }
}
