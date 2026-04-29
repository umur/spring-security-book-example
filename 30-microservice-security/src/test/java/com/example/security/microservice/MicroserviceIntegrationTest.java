package com.example.security.microservice;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Full integration test that:
 * - Starts a real PostgreSQL via Testcontainers
 * - Starts a WireMock server that simulates the authorization server
 *   (JWK set endpoint + token endpoint) and the external service
 * - Generates real RSA-signed JWTs for incoming request validation
 * - Tests the client_credentials flow: app obtains token from mock auth server
 *   and calls mock external service
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
class MicroserviceIntegrationTest {

    // ------------------------------------------------------------------
    // Infrastructure: PostgreSQL + WireMock
    // ------------------------------------------------------------------

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17-alpine");

    static WireMockServer wireMock;
    static RSAKey rsaKey;

    @BeforeAll
    static void startWireMock() throws Exception {
        rsaKey = new RSAKeyGenerator(2048)
                .keyID("test-key-id")
                .generate();

        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();

        stubJwkSet();
        stubTokenEndpoint();
        stubExternalServiceData();
    }

    @AfterAll
    static void stopWireMock() {
        if (wireMock != null) {
            wireMock.stop();
        }
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        // Database
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");

        // Point resource server JWK validation at WireMock
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> wireMock.baseUrl() + "/oauth2/jwks");

        // Point OAuth2 client token endpoint at WireMock
        registry.add("spring.security.oauth2.client.provider.auth-server.token-uri",
                () -> wireMock.baseUrl() + "/oauth2/token");

        // Point external service at WireMock
        registry.add("app.external-service.base-url", wireMock::baseUrl);
        registry.add("app.external-service.data-path", () -> "/api/external/data");

        // Auth server URIs used by properties
        registry.add("app.auth-server.jwk-set-uri",
                () -> wireMock.baseUrl() + "/oauth2/jwks");
        registry.add("app.auth-server.token-uri",
                () -> wireMock.baseUrl() + "/oauth2/token");
    }

    @Autowired
    TestRestTemplate restTemplate;

    // ------------------------------------------------------------------
    // WireMock stubs
    // ------------------------------------------------------------------

    private static void stubJwkSet() throws Exception {
        String jwkSetJson = "{\"keys\":[" + rsaKey.toPublicJWK().toJSONString() + "]}";
        wireMock.stubFor(get(urlEqualTo("/oauth2/jwks"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(jwkSetJson)));
    }

    private static void stubTokenEndpoint() {
        String tokenResponse = """
                {
                  "access_token": "mock-client-credentials-token",
                  "token_type": "Bearer",
                  "expires_in": 3600,
                  "scope": "internal.read"
                }
                """;
        wireMock.stubFor(post(urlEqualTo("/oauth2/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(tokenResponse)));
    }

    private static void stubExternalServiceData() {
        String externalDataResponse = """
                {
                  "service": "external-service",
                  "items": ["ext-item-1", "ext-item-2", "ext-item-3"]
                }
                """;
        wireMock.stubFor(get(urlEqualTo("/api/external/data"))
                .withHeader("Authorization", matching("Bearer .+"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(externalDataResponse)));
    }

    // ------------------------------------------------------------------
    // JWT helper
    // ------------------------------------------------------------------

    private String generateSignedJwt(String subject, String... scopes) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(wireMock.baseUrl())
                .audience("microservice-security-example")
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", String.join(" ", scopes))
                .build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(rsaKey.getKeyID())
                        .build(),
                claims
        );
        jwt.sign(new RSASSASigner(rsaKey));
        return jwt.serialize();
    }

    /** Builds an HttpEntity with a Bearer Authorization header and no body. */
    private static HttpEntity<Void> bearerAuth(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return new HttpEntity<>(headers);
    }

    // ------------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------------

    @Nested
    @DisplayName("GET /api/internal/data — JWT resource server validation")
    class InternalDataIntegration {

        @Test
        @DisplayName("returns 401 when no Authorization header is present")
        void returns401WithoutToken() {
            var response = restTemplate.getForEntity("/api/internal/data", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("returns 401 when a malformed token is presented")
        void returns401WithMalformedToken() {
            var response = restTemplate.exchange(
                    "/api/internal/data", HttpMethod.GET,
                    bearerAuth("this-is-not-a-jwt"), String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("returns 200 with a real RSA-signed JWT verified against the mock JWK set")
        void returns200WithValidRsaSignedJwt() throws Exception {
            String token = generateSignedJwt("service-alpha", "internal.read");

            var response = restTemplate.exchange(
                    "/api/internal/data", HttpMethod.GET,
                    bearerAuth(token), String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("microservice-security-example");
            assertThat(response.getBody()).contains("record-001");
        }

        @Test
        @DisplayName("returns 200 for any service principal with a valid token")
        void returns200ForDifferentServicePrincipal() throws Exception {
            String token = generateSignedJwt("service-beta", "other.scope");

            var response = restTemplate.exchange(
                    "/api/internal/data", HttpMethod.GET,
                    bearerAuth(token), String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }
    }

    @Nested
    @DisplayName("GET /api/aggregated — client credentials + external service call")
    class AggregatedIntegration {

        @Test
        @DisplayName("returns 401 when no Authorization header is present")
        void returns401WithoutToken() {
            var response = restTemplate.getForEntity("/api/aggregated", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("obtains client_credentials token, calls external service, returns aggregated data")
        void aggregatesDataUsingClientCredentials() throws Exception {
            String token = generateSignedJwt("api-gateway", "internal.read");

            var response = restTemplate.exchange(
                    "/api/aggregated", HttpMethod.GET,
                    bearerAuth(token), String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("microservice-security-example");
            assertThat(response.getBody()).contains("local-001");
            assertThat(response.getBody()).contains("external-service");
            assertThat(response.getBody()).contains("ext-item-1");

            // Verify the app actually called the mock token endpoint for client credentials
            wireMock.verify(postRequestedFor(urlEqualTo("/oauth2/token")));

            // Verify the app called the external service with a Bearer token
            wireMock.verify(getRequestedFor(urlEqualTo("/api/external/data"))
                    .withHeader("Authorization", matching("Bearer .+")));
        }

        @Test
        @DisplayName("token endpoint is called with client_credentials grant type")
        void tokenEndpointCalledWithClientCredentialsGrant() throws Exception {
            String token = generateSignedJwt("orchestrator-service", "internal.read");

            restTemplate.exchange(
                    "/api/aggregated", HttpMethod.GET,
                    bearerAuth(token), String.class);

            wireMock.verify(postRequestedFor(urlEqualTo("/oauth2/token"))
                    .withRequestBody(containing("grant_type=client_credentials")));
        }
    }
}
