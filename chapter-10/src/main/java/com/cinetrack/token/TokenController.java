package com.cinetrack.token;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;

/**
 * Demo token-issuance endpoints.
 *
 * These endpoints exist to make the PKCE and token-type concepts testable
 * without running a real authorization server. In production, tokens come
 * from Keycloak / Auth0 / Spring Authorization Server — not from the
 * resource server itself.
 *
 * client-credentials flow: the client authenticates with its own identity;
 * no end-user is involved. Audience is fixed to "cinetrack-catalog" because
 * catalog-service is the intended resource server for this chapter.
 *
 * authorization-code flow: simulates the token you would receive after the
 * authorization server exchanges the code for tokens on the user's behalf.
 */
@RestController
@RequestMapping("/api/token")
public class TokenController {

    private static final String AUDIENCE = "cinetrack-catalog";
    private static final long TOKEN_LIFETIME_SECONDS = 3600L;

    private final JwtEncoder jwtEncoder;

    public TokenController(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    /**
     * POST /api/token/client-credentials
     *
     * Issues a JWT with the requested scope and a fixed audience.
     * The subject is the clientId — no user identity is involved.
     */
    @PostMapping("/client-credentials")
    public TokenResponse clientCredentials(@RequestBody TokenRequest request) {
        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("http://localhost:8080")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(TOKEN_LIFETIME_SECONDS))
                .subject(request.clientId())
                .audience(List.of(AUDIENCE))
                .claim("scope", request.scope())
                .build();

        String token = encode(claims);
        return new TokenResponse(token, "Bearer", TOKEN_LIFETIME_SECONDS, request.scope());
    }

    /**
     * POST /api/token/authorization-code
     *
     * Simulates the token issued at the end of the authorization code flow.
     * The subject is the end-user (derived from clientId for demo purposes).
     * In a real AS the sub would be the authenticated user's ID.
     */
    @PostMapping("/authorization-code")
    public TokenResponse authorizationCode(@RequestBody TokenRequest request) {
        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("http://localhost:8080")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(TOKEN_LIFETIME_SECONDS))
                .subject("user:" + request.clientId())
                .audience(List.of(AUDIENCE))
                .claim("scope", request.scope())
                .claim("auth_time", now.getEpochSecond())
                .build();

        String token = encode(claims);
        return new TokenResponse(token, "Bearer", TOKEN_LIFETIME_SECONDS, request.scope());
    }

    private String encode(JwtClaimsSet claims) {
        JwsHeader header = JwsHeader.with(
                SignatureAlgorithm.RS256
        ).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
