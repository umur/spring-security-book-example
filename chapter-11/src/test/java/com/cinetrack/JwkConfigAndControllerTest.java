package com.cinetrack;

import com.cinetrack.catalog.CatalogController;
import com.cinetrack.catalog.MovieNotFoundException;
import com.cinetrack.security.CineTrackJwtConverter;
import com.cinetrack.security.JwkConfig;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Covers JwkConfig bean wiring, MovieNotFoundException, and the
 * CatalogController detail endpoint (movie-not-found branch).
 */
@WebMvcTest(CatalogController.class)
@Import({CatalogController.class, SecurityConfig.class, CineTrackJwtConverter.class,
        JwkConfigAndControllerTest.TestDecoderConfig.class})
@TestPropertySource(properties = {
        "cinetrack.security.issuer1-uri=http://localhost:8080/issuer1",
        "cinetrack.security.issuer2-uri=http://localhost:8080/issuer2"
})
class JwkConfigAndControllerTest {

    @Autowired
    MockMvc mockMvc;

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
    void movieNotFoundException_message_containsId() {
        MovieNotFoundException ex = new MovieNotFoundException(42L);
        assertThat(ex.getMessage()).contains("42");
    }

    @Test
    void catalogDetail_knownId_returnsMovieWithClaims() throws Exception {
        mockMvc.perform(get("/api/catalog/movies/1")
                        .with(jwt().jwt(b -> b
                                .issuer("http://localhost:8080/issuer1")
                                .subject("svc-account")
                                .claim("scope", "catalog:read")
                                .claim("tier", "PREMIUM"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.requestedBy").value("svc-account"))
                .andExpect(jsonPath("$.tier").value("PREMIUM"))
                .andExpect(jsonPath("$.movie.title").value("Inception"));
    }

    @Test
    void catalogDetail_missingTierClaim_defaultsToStandard() throws Exception {
        mockMvc.perform(get("/api/catalog/movies/2")
                        .with(jwt().jwt(b -> b
                                .issuer("http://localhost:8080/issuer1")
                                .subject("svc-no-tier")
                                .claim("scope", "catalog:read"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tier").value("STANDARD"));
    }

    @Test
    void catalogDetail_unknownId_returns404() throws Exception {
        mockMvc.perform(get("/api/catalog/movies/9999")
                        .with(jwt().jwt(b -> b
                                .issuer("http://localhost:8080/issuer1")
                                .subject("svc")
                                .claim("scope", "catalog:read"))))
                .andExpect(status().isNotFound());
    }

    @Test
    void scopeAsList_isExtractedCorrectly() throws Exception {
        // Exercises the List<?> branch of extractScopeAuthorities
        mockMvc.perform(get("/api/catalog/movies")
                        .with(jwt().jwt(b -> b
                                .issuer("http://localhost:8080/issuer1")
                                .subject("svc")
                                .claim("scope", java.util.List.of("catalog:read", "catalog:write")))))
                .andExpect(status().isOk());
    }

    @Test
    void jwkConfig_producesTwoIndependentKeys() throws Exception {
        JwkConfig config = new JwkConfig();
        RSAKey key1 = config.issuer1Key();
        RSAKey key2 = config.issuer2Key();
        assertThat(key1.getKeyID()).isEqualTo("issuer1-key");
        assertThat(key2.getKeyID()).isEqualTo("issuer2-key");
        assertThat(key1.toPublicJWK().toJSONString())
                .isNotEqualTo(key2.toPublicJWK().toJSONString());
    }

    @Test
    void jwkConfig_jwkSourceAndEncoderBeans_areNonNull() throws Exception {
        JwkConfig config = new JwkConfig();
        RSAKey key1 = config.issuer1Key();
        RSAKey key2 = config.issuer2Key();

        assertThat(config.issuer1JwkSource(key1)).isNotNull();
        assertThat(config.issuer2JwkSource(key2)).isNotNull();
        assertThat(config.issuer1JwtDecoder(key1)).isNotNull();
        assertThat(config.issuer2JwtDecoder(key2)).isNotNull();
        assertThat(config.issuer1JwtEncoder(config.issuer1JwkSource(key1))).isNotNull();
        assertThat(config.issuer2JwtEncoder(config.issuer2JwkSource(key2))).isNotNull();
    }
}
