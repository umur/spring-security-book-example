package com.cinetrack.security;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;

/**
 * Rejects any JWT whose {@code aud} claim does not contain the expected
 * service identifier.
 *
 * Zero-trust service meshes issue service-specific tokens: a token minted
 * for {@code recommendation-service} must not be accepted by
 * {@code catalog-service}. Audience validation is the enforcement point.
 *
 * Spring Security's {@link org.springframework.security.oauth2.jwt.JwtValidators}
 * already validates expiry and issuer; this validator adds the audience check
 * on top of the default chain: see {@link ServiceSecurityConfig}.
 */
public class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error AUDIENCE_ERROR = new OAuth2Error(
            "invalid_token",
            "JWT audience does not include required service identifier",
            null
    );

    private final String requiredAudience;

    public AudienceValidator(String requiredAudience) {
        this.requiredAudience = requiredAudience;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        List<String> audiences = jwt.getAudience();
        if (audiences != null && audiences.contains(requiredAudience)) {
            return OAuth2TokenValidatorResult.success();
        }
        return OAuth2TokenValidatorResult.failure(AUDIENCE_ERROR);
    }
}
