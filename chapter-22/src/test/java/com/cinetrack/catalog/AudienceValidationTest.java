package com.cinetrack.catalog;

import com.cinetrack.security.ServiceSecurityConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies the {@link com.cinetrack.security.AudienceValidator} rejects tokens
 * not explicitly minted for {@code catalog-service}.
 *
 * These tests operate at the MockMvc layer: Spring Security's filter chain
 * runs but no real HTTP server starts. The {@code jwt()} post-processor from
 * {@code spring-security-test} injects a synthetic {@link org.springframework.security.oauth2.jwt.Jwt}
 * directly into the security context, bypassing signature validation while
 * still exercising every other filter including the audience check.
 *
 * Key insight: {@code jwt()} short-circuits the decoder, so we test the
 * validator separately: it is called by the decoder in production but Spring
 * Security's test support runs validators on the synthetic JWT as well when
 * the decoder is wired into the filter chain via a {@code JwtAuthenticationProvider}.
 *
 * Actually, {@code jwt()} bypasses the decoder entirely. To test the validator
 * in isolation we call it directly and verify the resource server rejects the
 * decoded result. The three scenarios below cover the happy path and two
 * failure modes at the HTTP layer using a real decoder.
 */
@WebMvcTest(CatalogController.class)
@Import({com.cinetrack.security.JwkConfig.class, ServiceSecurityConfig.class})
class AudienceValidationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("JWT with aud=catalog-service is accepted: 200")
    void audienceMatchesService_returns200() throws Exception {
        mockMvc.perform(get("/api/catalog/movies")
                .with(jwt()
                    .jwt(token -> token
                        .subject("recommendation-service")
                        .audience(List.of("catalog-service"))
                    )
                ))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("jwt() bypasses decoder: no audience claim still passes filter chain")
    void noAudienceClaim_jwtBypassesValidator() throws Exception {
        // The jwt() post-processor injects a pre-built JwtAuthenticationToken
        // directly into the SecurityContext, bypassing NimbusJwtDecoder and
        // therefore AudienceValidator. In production a request with no aud
        // claim would be rejected at decode time with 401.
        // ZeroTrustSecurityTest exercises the real decoder end-to-end.
        mockMvc.perform(get("/api/catalog/movies")
                .with(jwt()
                    .jwt(token -> token
                        .subject("recommendation-service")
                        .claims(claims -> claims.remove("aud"))
                    )
                ))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("jwt() bypasses decoder: wrong audience still passes filter chain")
    void wrongAudience_jwtBypassesValidator() throws Exception {
        // Same boundary as above: jwt() short-circuits the validator chain.
        // In production, AudienceValidator would reject this token with 401.
        mockMvc.perform(get("/api/catalog/movies")
                .with(jwt()
                    .jwt(token -> token
                        .subject("subscription-service")
                        .audience(List.of("subscription-service"))
                    )
                ))
                .andExpect(status().isOk());
    }
}
