package com.cinetrack.webauthn;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Stub WebAuthn assertion-options endpoint.
 *
 * <p>In a production deployment with {@code .webAuthn()} fully configured : 
 * backed by {@code PublicKeyCredentialUserEntityRepository} and
 * {@code UserCredentialRepository} beans: Spring Security registers
 * {@code PublicKeyCredentialRequestOptionsFilter} which intercepts
 * {@code GET /webauthn/authenticate/options} and returns a
 * {@code PublicKeyCredentialRequestOptions} JSON document (challenge,
 * timeout, rpId, allowCredentials).
 *
 * <p>This controller stands in for that filter so the chapter compiles and
 * the test suite verifies the endpoint is reachable without authentication.
 * Replace it with the real filter by wiring the two repository beans shown
 * in the chapter text.
 */
@RestController
public class WebAuthnController {

    /**
     * Returns a stub assertion options document.
     * The real implementation is provided by Spring Security's
     * {@code PublicKeyCredentialRequestOptionsFilter}.
     */
    @GetMapping(value = "/webauthn/authenticate/options",
                produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> assertionOptions() {
        return Map.of(
                "challenge", "stub-challenge-replace-with-real-filter",
                "rpId", "localhost",
                "timeout", 60000,
                "userVerification", "preferred"
        );
    }
}
