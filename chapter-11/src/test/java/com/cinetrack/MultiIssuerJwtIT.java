package com.cinetrack;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Chapter 11: Multi-issuer JWT end-to-end integration test.
 *
 * The chapter uses two in-process RSA key pairs (JwkConfig) to simulate
 * issuer-a and issuer-b. This IT:
 *
 *   1. Starts the full Spring Boot application on a random port.
 *   2. Mints real, cryptographically signed JWTs using the two in-process
 *      JwtEncoder beans (issuer1JwtEncoder, issuer2JwtEncoder).
 *   3. Presents each token to the /api/catalog/movies endpoint via a real
 *      HTTP call - no MockMvc security shortcuts.
 *   4. Asserts 200 for tokens from both registered issuers.
 *   5. Asserts 401 for a token signed with an unknown third-party key
 *      (not in the resolver map).
 *
 * No external IdP container is needed: the in-process JwkConfig already
 * provides both issuers' key material. Testcontainers is on the classpath
 * but not activated here; the in-process approach is the correct architecture
 * for this chapter's self-contained design.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "cinetrack.security.issuer1-uri=http://issuer-a.cinetrack.test",
        "cinetrack.security.issuer2-uri=http://issuer-b.cinetrack.test"
})
@Testcontainers
class MultiIssuerJwtIT {

    static final String ISSUER_A = "http://issuer-a.cinetrack.test";
    static final String ISSUER_B = "http://issuer-b.cinetrack.test";

    @LocalServerPort
    int port;

    @Autowired
    JwtEncoder issuer1JwtEncoder;

    @Autowired
    JwtEncoder issuer2JwtEncoder;

    // ── helpers ───────────────────────────────────────────────────────────────

    private String mintToken(JwtEncoder encoder, String issuer, String subject, String scope) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(subject)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .claim("scope", scope)
                .build();
        return encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    private ResponseEntity<String> callCatalog(String bearerToken) {
        RestTemplate rest = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(bearerToken);
        return rest.exchange(
                "http://localhost:" + port + "/api/catalog/movies",
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class
        );
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Token from issuer-a with catalog:read scope returns 200")
    void issuerA_validToken_returns200() {
        String token = mintToken(issuer1JwtEncoder, ISSUER_A, "client-a", "catalog:read");
        ResponseEntity<String> response = callCatalog(token);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("Inception");
    }

    @Test
    @DisplayName("Token from issuer-b with catalog:read scope returns 200")
    void issuerB_validToken_returns200() {
        String token = mintToken(issuer2JwtEncoder, ISSUER_B, "client-b", "catalog:read");
        ResponseEntity<String> response = callCatalog(token);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("Inception");
    }

    @Test
    @DisplayName("Token from unknown issuer returns 401")
    void unknownIssuer_token_returns401() throws Exception {
        // Generate a completely foreign key pair not registered with either issuer
        RSAKey foreignKey = new RSAKeyGenerator(2048).keyID("foreign-key").generate();
        JWKSet foreignJwkSet = new JWKSet(foreignKey);
        ImmutableJWKSet<com.nimbusds.jose.proc.SecurityContext> foreignSource =
                new ImmutableJWKSet<>(foreignJwkSet);
        JwtEncoder foreignEncoder = new NimbusJwtEncoder(foreignSource);

        // Token claims an unknown issuer - not in the resolver map
        String token = mintToken(foreignEncoder,
                "http://unknown-issuer.example.com", "attacker", "catalog:read");

        RestTemplate rest = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        assertThatThrownBy(() ->
                rest.exchange(
                        "http://localhost:" + port + "/api/catalog/movies",
                        HttpMethod.GET,
                        new HttpEntity<>(headers),
                        String.class
                )
        ).isInstanceOf(HttpClientErrorException.Unauthorized.class);
    }

    @Test
    @DisplayName("Request without token returns 401")
    void noToken_returns401() {
        RestTemplate rest = new RestTemplate();
        assertThatThrownBy(() ->
                rest.getForEntity(
                        "http://localhost:" + port + "/api/catalog/movies",
                        String.class
                )
        ).isInstanceOf(HttpClientErrorException.Unauthorized.class);
    }
}
