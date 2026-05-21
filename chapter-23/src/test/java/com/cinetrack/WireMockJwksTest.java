package com.cinetrack;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end JWT validation using WireMock to serve a real JWKS endpoint.
 *
 * WireMockServer is started statically so keys are generated and stubbed once
 * per test class: before any test instance is created. A nested
 * {@link JwtDecoderOverride} {@code @TestConfiguration} replaces the
 * in-process {@code JwkConfig} decoder with one that fetches keys from
 * WireMock, exercising the full remote JWKS fetch-and-validate path.
 *
 * The RSA key is generated once in {@code @BeforeAll} (static) so the decoder's
 * JWKS cache remains consistent across all tests in this class.
 *
 * {@code @TestPropertySource} gives this context a unique cache key so it
 * runs in isolation from the catalog-package WireMockJwksTest.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@TestPropertySource(properties = "test.isolation=root-wm")
class WireMockJwksTest {

    private static WireMockServer wireMock;
    private static RSAKey rsaKey;

    @Autowired
    private MockMvc mockMvc;

    /**
     * Replaces {@code JwkConfig}'s in-process decoder with one that fetches the
     * JWKS from WireMock. {@code @Primary} ensures Spring Security's
     * {@code JwtAuthenticationProvider} uses this decoder over any other candidate.
     */
    @TestConfiguration
    static class JwtDecoderOverride {

        @Bean
        @Primary
        JwtDecoder wireMockJwtDecoder() {
            return NimbusJwtDecoder
                    .withJwkSetUri(wireMock.baseUrl() + "/.well-known/jwks.json")
                    .build();
        }
    }

    @BeforeAll
    static void startWireMock() throws Exception {
        wireMock = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        wireMock.start();

        rsaKey = new RSAKeyGenerator(2048).keyID("test-key").generate();
        String jwksJson = new JWKSet(rsaKey.toPublicJWK()).toString();

        wireMock.stubFor(WireMock.get(urlEqualTo("/.well-known/jwks.json"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                        .withBody(jwksJson)));
    }

    @AfterAll
    static void stopWireMock() {
        wireMock.stop();
    }

    @Test
    @DisplayName("Valid signed JWT verified against WireMock JWKS returns 200")
    void validSignedJwt_returnsOk() throws Exception {
        String token = mintToken(Instant.now().plusSeconds(60), List.of("catalog:read"));

        mockMvc.perform(get("/api/catalog/movies")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Expired JWT is rejected with 401")
    void expiredJwt_returnsUnauthorized() throws Exception {
        String token = mintToken(Instant.now().minusSeconds(60), List.of("catalog:read"));

        mockMvc.perform(get("/api/catalog/movies")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    // ---- helpers --------------------------------------------------------

    private String mintToken(Instant expiry, List<String> scopes) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("test-user")
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(expiry))
                .claim("scope", String.join(" ", scopes))
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaKey.getKeyID())
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new RSASSASigner(rsaKey));
        return jwt.serialize();
    }
}
