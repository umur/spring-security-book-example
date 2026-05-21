package com.cinetrack.mfa;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

/**
 * Generates and validates TOTP codes using the java-otp library.
 *
 * The generator is configured with the RFC 6238 defaults: SHA-1 HMAC,
 * 6-digit codes, and a 30-second time step. Each validation window accepts
 * one step before and one step after the current period to account for
 * clock skew between the user's authenticator app and the server.
 */
@Service
public class TotpService {

    private static final int CODE_DIGITS = 6;
    private static final Duration TIME_STEP = Duration.ofSeconds(30);
    private static final String HMAC_ALGORITHM = "HmacSHA1";

    private final TimeBasedOneTimePasswordGenerator totp;

    public TotpService() {
        // TimeBasedOneTimePasswordGenerator constructor does not declare
        // checked exceptions in java-otp 0.4.0; it uses the default algorithm.
        this.totp = new TimeBasedOneTimePasswordGenerator(TIME_STEP, CODE_DIGITS);
    }

    /**
     * Generates a new random Base64-encoded secret suitable for use as a TOTP
     * shared secret. In production this would be stored encrypted at rest.
     */
    public String generateSecret() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(HMAC_ALGORITHM);
            keyGenerator.init(160); // 160-bit key for SHA-1
            SecretKey key = keyGenerator.generateKey();
            return Base64.getEncoder().encodeToString(key.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Key generation failed", e);
        }
    }

    /**
     * Returns true if {@code code} is the valid TOTP for {@code secret} at
     * the current instant, accepting a one-step tolerance window (±30 s).
     *
     * @param secret Base64-encoded or raw ASCII secret, as stored in MfaUser
     * @param code   6-digit string from the authenticator app
     */
    public boolean isValid(String secret, String code) {
        if (secret == null || code == null || code.length() != CODE_DIGITS) {
            return false;
        }
        try {
            SecretKey key = decodeSecret(secret);
            Instant now = Instant.now();

            // Check current step and adjacent steps for clock-skew tolerance.
            for (int offset = -1; offset <= 1; offset++) {
                Instant window = now.plus(TIME_STEP.multipliedBy(offset));
                int expected = totp.generateOneTimePassword(key, window);
                String expectedString = String.format("%0" + CODE_DIGITS + "d", expected);
                if (expectedString.equals(code)) {
                    return true;
                }
            }
            return false;
        } catch (InvalidKeyException e) {
            return false;
        }
    }

    /**
     * Generates the current TOTP code for a given secret. Used in tests to
     * produce a fresh code without depending on an authenticator app.
     */
    public String generateCode(String secret) {
        try {
            SecretKey key = decodeSecret(secret);
            int code = totp.generateOneTimePassword(key, Instant.now());
            return String.format("%0" + CODE_DIGITS + "d", code);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Code generation failed", e);
        }
    }

    private SecretKey decodeSecret(String secret) {
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(secret);
        } catch (IllegalArgumentException e) {
            // Fall back to raw ASCII bytes for pre-encoded test secrets.
            keyBytes = secret.getBytes(StandardCharsets.US_ASCII);
        }
        return new SecretKeySpec(keyBytes, HMAC_ALGORITHM);
    }
}
