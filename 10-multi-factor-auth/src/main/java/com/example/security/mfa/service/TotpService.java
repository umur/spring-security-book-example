package com.example.security.mfa.service;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

/**
 * TOTP (Time-based One-Time Password) implementation per RFC 6238.
 * Compatible with Google Authenticator and similar apps.
 */
@Service
public class TotpService {

    private static final int TIME_STEP_SECONDS = 30;
    private static final int CODE_DIGITS = 6;
    private static final int WINDOW = 1; // allow 1 step before/after for clock skew
    private static final String HMAC_ALGORITHM = "HmacSHA1";

    public String generateSecret() {
        byte[] bytes = new byte[20];
        new SecureRandom().nextBytes(bytes);
        return Base64.getEncoder().withoutPadding().encodeToString(bytes);
    }

    public String buildQrCodeUrl(String username, String secret) {
        String issuer = "SpringSecurityExamples";
        String encodedIssuer = urlEncode(issuer);
        String encodedUsername = urlEncode(username);
        String encodedSecret = urlEncode(secret);
        return String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
                encodedIssuer, encodedUsername, encodedSecret, encodedIssuer
        );
    }

    public boolean verifyCode(String secret, int code) {
        long currentStep = Instant.now().getEpochSecond() / TIME_STEP_SECONDS;
        for (int delta = -WINDOW; delta <= WINDOW; delta++) {
            if (generateCode(secret, currentStep + delta) == code) {
                return true;
            }
        }
        return false;
    }

    private int generateCode(String secret, long timeStep) {
        byte[] key = Base64.getDecoder().decode(secret);
        byte[] msg = longToBytes(timeStep);
        byte[] hash = hmacSha1(key, msg);
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);
        int mod = (int) Math.pow(10, CODE_DIGITS);
        return binary % mod;
    }

    private byte[] hmacSha1(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HMAC-SHA1 not available", e);
        }
    }

    private byte[] longToBytes(long value) {
        byte[] result = new byte[8];
        for (int i = 7; i >= 0; i--) {
            result[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        return result;
    }

    private String urlEncode(String value) {
        return value.replace(" ", "%20").replace(":", "%3A").replace("@", "%40");
    }
}
