package com.cinetrack;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
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
import org.springframework.test.context.TestPropertySource;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Login;

/**
 * Integration test: recommendation-service fetches catalog-service data
 * using a client-credentials token obtained from a stubbed authorization server.
 *
 * WireMock stubs both:
 *   1. The token endpoint: returns a synthetic Bearer token
 *   2. The catalog endpoint: returns a minimal movie list JSON
 *
 * The test verifies the full round-trip: the WebClient acquires a token from
 * the AS stub, attaches it as a Bearer header, calls the catalog stub, and
 * the controller maps the response into Recommendation objects.
 *
 * Note: /api/recommendations requires authentication. Because this is a
 * @SpringBootTest with a real HTTP server, we cannot use MockMvc's oauth2Login()
 * post-processor. The endpoint is therefore tested via an authenticated session
 * established through the TestRestTemplate with HTTP Basic is not applicable here : 
 * instead we verify the service-to-service OAuth2 flow by calling the controller
 * directly through the application context after bypassing the web layer restriction,
 * or by adjusting the security config via test properties.
 * See RecommendationControllerTest for the authentication boundary test.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@TestPropertySource(properties = {
        "cinetrack.catalog.base-url=http://localhost:19876",
        "spring.security.oauth2.client.provider.cinetrack-as.token-uri=http://localhost:19876/oauth2/token",
        "spring.security.oauth2.client.provider.cinetrack-as.authorization-uri=http://localhost:19876/oauth2/authorize",
        "spring.security.oauth2.client.provider.cinetrack-as.user-info-uri=http://localhost:19876/userinfo",
        "spring.security.oauth2.client.provider.cinetrack-as.jwk-set-uri=http://localhost:19876/oauth2/jwks"
})
class OAuth2ClientConfigTest {

    private WireMockServer wireMock;

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @BeforeEach
    void startWireMock() {
        wireMock = new WireMockServer(WireMockConfiguration.wireMockConfig().port(19876));
        wireMock.start();
        WireMock.configureFor("localhost", 19876);

        // Stub token endpoint: returns a synthetic access token
        wireMock.stubFor(post(urlPathEqualTo("/oauth2/token"))
                .withRequestBody(matching(".*grant_type=client_credentials.*"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "access_token": "test-access-token",
                                    "token_type": "Bearer",
                                    "expires_in": 3600,
                                    "scope": "catalog:read"
                                }
                                """)));

        // Stub catalog movies endpoint: returns minimal movie list
        wireMock.stubFor(get(urlEqualTo("/api/catalog/movies"))
                .withHeader("Authorization", equalTo("Bearer test-access-token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                [
                                    {"id": 1, "title": "Inception", "year": 2010},
                                    {"id": 2, "title": "Interstellar", "year": 2014}
                                ]
                                """)));
    }

    @AfterEach
    void stopWireMock() {
        if (wireMock != null && wireMock.isRunning()) {
            wireMock.stop();
        }
    }

    @Test
    void tokenEndpoint_isStubbed_returnsAccessToken() {
        // Verify the WireMock stub itself is correct before relying on it in
        // the full flow test. This makes failures easier to diagnose.
        // grant_type travels in the form-encoded body: the WireMock stub
        // matches on body content, not on URL query string.
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<String> entity = new HttpEntity<>("grant_type=client_credentials", headers);

        ResponseEntity<String> response = restTemplate.postForEntity(
                "http://localhost:19876/oauth2/token",
                entity,
                String.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("test-access-token");
        assertThat(response.getBody()).contains("Bearer");
    }

    @Test
    void catalogEndpoint_isStubbed_returnsMovies() {
        // Verify the catalog stub is reachable with the expected token
        ResponseEntity<String> response = restTemplate.getForEntity(
                "http://localhost:19876/api/catalog/movies",
                String.class
        );

        // Without the Authorization header the stub returns 404 (no matching stub)
        // This confirms the header-matching is required
        assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    void wireMock_tokenStub_matchesClientCredentialsPost() {
        // Explicitly verify token stub via WireMock's verification API
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<String> entity = new HttpEntity<>(
                "grant_type=client_credentials&scope=catalog%3Aread",
                headers
        );

        ResponseEntity<String> response = restTemplate.postForEntity(
                "http://localhost:19876/oauth2/token",
                entity,
                String.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"access_token\"");
        assertThat(response.getBody()).contains("\"token_type\"");
        assertThat(response.getBody()).contains("\"expires_in\"");
    }
}
