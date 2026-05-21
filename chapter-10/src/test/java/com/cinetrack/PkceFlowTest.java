package com.cinetrack;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the PKCE (Proof Key for Code Exchange) mathematics: RFC 7636.
 *
 * PKCE prevents authorization code interception attacks. The client generates
 * a random code_verifier, derives a code_challenge from it using SHA-256, and
 * sends the challenge in the authorization request. When it later redeems the
 * code, it sends the verifier; the AS recomputes the challenge and compares.
 *
 * No Spring context is needed: this is pure cryptography.
 */
class PkceFlowTest {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Generates a code_verifier that satisfies RFC 7636 constraints:
     *   - 43–128 characters of unreserved ASCII (A-Z a-z 0-9 - . _ ~)
     *   - Sufficient entropy: at least 256 bits recommended
     */
    private String generateCodeVerifier() {
        byte[] randomBytes = new byte[64]; // 512 bits of entropy
        SECURE_RANDOM.nextBytes(randomBytes);
        // Base64URL without padding produces characters from the unreserved set
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Derives the code_challenge from the verifier using S256 method:
     *   code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
     */
    private String deriveCodeChallenge(String codeVerifier) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    @Test
    void codeVerifier_hasValidLength() {
        String verifier = generateCodeVerifier();

        assertThat(verifier.length())
                .as("code_verifier must be between 43 and 128 characters (RFC 7636 §4.1)")
                .isBetween(43, 128);
    }

    @Test
    void codeVerifier_containsOnlyUnreservedCharacters() {
        String verifier = generateCodeVerifier();

        // RFC 7636 §4.1: ALPHA / DIGIT / "-" / "." / "_" / "~"
        assertThat(verifier).matches("[A-Za-z0-9\\-._~]+");
    }

    @Test
    void codeChallenge_isProducedFromVerifierViaSha256() throws Exception {
        String verifier = generateCodeVerifier();
        String challenge = deriveCodeChallenge(verifier);

        // A SHA-256 hash Base64URL-encoded without padding is always 43 chars
        assertThat(challenge).hasSize(43);
    }

    @Test
    void sameVerifier_producesIdenticalChallenge() throws Exception {
        String verifier = generateCodeVerifier();
        String challenge1 = deriveCodeChallenge(verifier);
        String challenge2 = deriveCodeChallenge(verifier);

        // The derivation is deterministic: the AS can recompute and compare
        assertThat(challenge1).isEqualTo(challenge2);
    }

    @Test
    void differentVerifiers_produceDifferentChallenges() throws Exception {
        String verifier1 = generateCodeVerifier();
        String verifier2 = generateCodeVerifier();
        String challenge1 = deriveCodeChallenge(verifier1);
        String challenge2 = deriveCodeChallenge(verifier2);

        // Two verifiers must not collide: intercept attack impossible
        assertThat(challenge1).isNotEqualTo(challenge2);
    }

    @RepeatedTest(5)
    void pkceRoundTrip_verifierAndChallengeAreConsistent() throws Exception {
        // This is what the AS does: recompute the challenge and compare
        String verifier = generateCodeVerifier();
        String challengeSentByClient = deriveCodeChallenge(verifier);
        String challengeRecomputedByServer = deriveCodeChallenge(verifier);

        assertThat(challengeRecomputedByServer)
                .as("AS must accept the code when verifier matches the stored challenge")
                .isEqualTo(challengeSentByClient);
    }

    @Test
    void tampered_verifier_producesWrongChallenge() throws Exception {
        String verifier = generateCodeVerifier();
        String originalChallenge = deriveCodeChallenge(verifier);

        // Attacker intercepts code and tries with a different verifier
        String tamperedVerifier = generateCodeVerifier();
        String tamperedChallenge = deriveCodeChallenge(tamperedVerifier);

        assertThat(tamperedChallenge)
                .as("A tampered verifier must not match the original challenge")
                .isNotEqualTo(originalChallenge);
    }

    @Test
    void codeChallenge_isUrlSafeBase64WithoutPadding() throws Exception {
        String verifier = generateCodeVerifier();
        String challenge = deriveCodeChallenge(verifier);

        // Base64URL alphabet: A-Z a-z 0-9 - _ (no + / = padding)
        assertThat(challenge).matches("[A-Za-z0-9\\-_]+");
        assertThat(challenge).doesNotContain("=", "+", "/");
    }
}
