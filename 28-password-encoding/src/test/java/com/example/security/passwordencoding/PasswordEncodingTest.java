package com.example.security.passwordencoding;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plain JUnit 5 unit tests — no Spring context required.
 * Verifies that each encoder encodes and matches correctly, and that
 * DelegatingPasswordEncoder correctly routes via the {prefix}.
 */
@DisplayName("Password Encoding Unit Tests")
class PasswordEncodingTest {

    private static final String RAW = "mySecret123!";

    @Nested
    @DisplayName("BCryptPasswordEncoder")
    class BCrypt {

        private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(10);

        @Test
        @DisplayName("encodes and matches correctly")
        void encodesAndMatches() {
            String encoded = encoder.encode(RAW);
            assertThat(encoder.matches(RAW, encoded)).isTrue();
        }

        @Test
        @DisplayName("two encodings of the same password produce different hashes")
        void differentHashesEachTime() {
            String hash1 = encoder.encode(RAW);
            String hash2 = encoder.encode(RAW);
            assertThat(hash1).isNotEqualTo(hash2);
        }

        @Test
        @DisplayName("wrong password does not match")
        void wrongPasswordDoesNotMatch() {
            String encoded = encoder.encode(RAW);
            assertThat(encoder.matches("wrongPassword", encoded)).isFalse();
        }
    }

    @Nested
    @DisplayName("Argon2PasswordEncoder")
    class Argon2 {

        private final Argon2PasswordEncoder encoder =
                Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();

        @Test
        @DisplayName("encodes and matches correctly")
        void encodesAndMatches() {
            String encoded = encoder.encode(RAW);
            assertThat(encoder.matches(RAW, encoded)).isTrue();
        }

        @Test
        @DisplayName("two encodings of the same password produce different hashes")
        void differentHashesEachTime() {
            String hash1 = encoder.encode(RAW);
            String hash2 = encoder.encode(RAW);
            assertThat(hash1).isNotEqualTo(hash2);
        }

        @Test
        @DisplayName("wrong password does not match")
        void wrongPasswordDoesNotMatch() {
            String encoded = encoder.encode(RAW);
            assertThat(encoder.matches("wrongPassword", encoded)).isFalse();
        }
    }

    @Nested
    @DisplayName("DelegatingPasswordEncoder")
    class Delegating {

        private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(10);
        private final PasswordEncoder delegating;

        Delegating() {
            Map<String, PasswordEncoder> encoders = Map.of(
                    "bcrypt", bcrypt,
                    "argon2", Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(),
                    "pbkdf2", Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8(),
                    "scrypt", SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8()
            );
            delegating = new DelegatingPasswordEncoder("bcrypt", encoders);
        }

        @Test
        @DisplayName("encoded value contains {bcrypt} prefix when default encoder is bcrypt")
        void encodedValueContainsBcryptPrefix() {
            String encoded = delegating.encode(RAW);
            assertThat(encoded).startsWith("{bcrypt}");
        }

        @Test
        @DisplayName("matches a bcrypt-prefixed encoded value")
        void matchesBcryptPrefixedHash() {
            // Simulate a hash that was stored with {bcrypt} prefix
            String bcryptHash = bcrypt.encode(RAW);
            String prefixed = "{bcrypt}" + bcryptHash;
            assertThat(delegating.matches(RAW, prefixed)).isTrue();
        }

        @Test
        @DisplayName("matches its own encoded output")
        void matchesOwnOutput() {
            String encoded = delegating.encode(RAW);
            assertThat(delegating.matches(RAW, encoded)).isTrue();
        }

        @Test
        @DisplayName("wrong password does not match delegating-encoded hash")
        void wrongPasswordDoesNotMatch() {
            String encoded = delegating.encode(RAW);
            assertThat(delegating.matches("wrongPassword", encoded)).isFalse();
        }

        @Test
        @DisplayName("PasswordEncoderFactories.createDelegatingPasswordEncoder produces {bcrypt} prefix")
        void factoryMethodProducesBcryptPrefix() {
            PasswordEncoder factory = PasswordEncoderFactories.createDelegatingPasswordEncoder();
            String encoded = factory.encode(RAW);
            assertThat(encoded).startsWith("{bcrypt}");
            assertThat(factory.matches(RAW, encoded)).isTrue();
        }
    }
}
