package com.cinetrack.password;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for password encoding behaviour.
 *
 * No Spring context is loaded -- BCryptPasswordEncoder and
 * DelegatingPasswordEncoder are plain Java objects and can be exercised
 * without any application context overhead.
 */
class PasswordEncodingTest {

    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(12);

    // -----------------------------------------------------------------------
    // BCryptPasswordEncoder
    // -----------------------------------------------------------------------

    @Test
    void bcrypt_encodesPassword() {
        String encoded = bcrypt.encode("my-secret");

        assertThat(encoded).isNotNull().isNotEmpty();
        assertThat(encoded).startsWith("$2a$12$");
    }

    @Test
    void bcrypt_matches_returnsTrue_forCorrectPassword() {
        String encoded = bcrypt.encode("correct-horse-battery-staple");

        assertThat(bcrypt.matches("correct-horse-battery-staple", encoded)).isTrue();
    }

    @Test
    void bcrypt_matches_returnsFalse_forWrongPassword() {
        String encoded = bcrypt.encode("correct-horse-battery-staple");

        assertThat(bcrypt.matches("wrong-password", encoded)).isFalse();
    }

    // -----------------------------------------------------------------------
    // DelegatingPasswordEncoder
    // -----------------------------------------------------------------------

    @Test
    void delegatingEncoder_recognizesBcryptPrefixedHash() {
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("bcrypt", new BCryptPasswordEncoder(12));
        DelegatingPasswordEncoder delegate = new DelegatingPasswordEncoder("bcrypt", encoders);

        // Encode a password so we get a {bcrypt}-prefixed hash.
        String encoded = delegate.encode("my-secret");
        assertThat(encoded).startsWith("{bcrypt}");

        // The delegate must be able to verify a {bcrypt} hash even when the
        // default encoder changes -- this is the migration-friendly property.
        assertThat(delegate.matches("my-secret", encoded)).isTrue();
    }
}
