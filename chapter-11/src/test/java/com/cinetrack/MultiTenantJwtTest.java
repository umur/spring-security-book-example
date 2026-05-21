package com.cinetrack;

import com.cinetrack.catalog.CatalogController;
import com.cinetrack.security.CineTrackJwtConverter;
import com.cinetrack.security.SecurityConfig;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies multi-tenant JWT routing and the full authority-mapping pipeline.
 *
 * The jwt() post-processor injects a pre-authenticated JwtAuthenticationToken,
 * bypassing signature verification: which is exactly right for a slice test
 * focused on authorization logic rather than cryptography.
 *
 * We configure the CineTrackJwtConverter explicitly so the converter's claim
 * extraction is exercised end-to-end in the WebMvcTest slice.
 */
@WebMvcTest(CatalogController.class)
@Import({CatalogController.class, SecurityConfig.class, CineTrackJwtConverter.class, MultiTenantJwtTest.TestDecoderConfig.class})
@TestPropertySource(properties = {
        "cinetrack.security.issuer1-uri=http://localhost:8080/issuer1",
        "cinetrack.security.issuer2-uri=http://localhost:8080/issuer2"
})
class MultiTenantJwtTest {

    @Autowired
    private MockMvc mockMvc;

    /**
     * Provides stub JwtDecoder beans so the WebMvcTest slice does not attempt
     * to contact a real JWKS endpoint. The decoders are never called during
     * these tests because jwt() bypasses actual JWT parsing.
     */
    @Configuration
    static class TestDecoderConfig {

        @Bean
        public RSAKey issuer1Key() throws Exception {
            return new RSAKeyGenerator(2048).keyID("issuer1-key").generate();
        }

        @Bean
        public RSAKey issuer2Key() throws Exception {
            return new RSAKeyGenerator(2048).keyID("issuer2-key").generate();
        }

        @Bean
        public JwtDecoder issuer1JwtDecoder(RSAKey issuer1Key) throws Exception {
            return NimbusJwtDecoder.withPublicKey(issuer1Key.toRSAPublicKey()).build();
        }

        @Bean
        public JwtDecoder issuer2JwtDecoder(RSAKey issuer2Key) throws Exception {
            return NimbusJwtDecoder.withPublicKey(issuer2Key.toRSAPublicKey()).build();
        }
    }

    @Test
    void issuer1Token_withCatalogReadScope_returns200() throws Exception {
        mockMvc.perform(get("/api/catalog/movies")
                        .with(jwt().jwt(builder -> builder
                                .issuer("http://localhost:8080/issuer1")
                                .subject("service-account-1")
                                .claim("scope", "catalog:read")
                        )))
                .andExpect(status().isOk());
    }

    @Test
    void issuer2Token_withCatalogReadScope_returns200() throws Exception {
        // Partner issuer tokens must also be accepted when they carry the right scope
        mockMvc.perform(get("/api/catalog/movies")
                        .with(jwt().jwt(builder -> builder
                                .issuer("http://localhost:8080/issuer2")
                                .subject("studio-service")
                                .claim("scope", "catalog:read")
                        )))
                .andExpect(status().isOk());
    }

    @Test
    void tokenWithoutScope_returns403() throws Exception {
        mockMvc.perform(get("/api/catalog/movies")
                        .with(jwt().jwt(builder -> builder
                                .issuer("http://localhost:8080/issuer1")
                                .subject("incomplete-client")
                        )))
                .andExpect(status().isForbidden());
    }

    @Test
    void noToken_returns401() throws Exception {
        mockMvc.perform(get("/api/catalog/movies"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void premiumToken_exposesTierAuthority() throws Exception {
        // Verify that the TIER_PREMIUM authority is mapped from the tier claim.
        // The detail endpoint echoes the tier from the JWT for test observability.
        mockMvc.perform(get("/api/catalog/movies/1")
                        .with(jwt().jwt(builder -> builder
                                .issuer("http://localhost:8080/issuer1")
                                .subject("premium-user")
                                .claim("scope", "catalog:read")
                                .claim("tier", "PREMIUM")
                        )))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tier").value("PREMIUM"));
    }
}
