package com.cinetrack.crypto;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;
import java.util.Map;

/**
 * Exposes password-encoding beans used throughout Chapter 5.
 *
 * Two beans are declared:
 *
 * 1. {@code BCryptPasswordEncoder} at strength 12 -- the standard choice for
 *    new Spring Boot applications.  Strength 12 requires ~300 ms per hash on
 *    modern hardware, which is an acceptable trade-off between security and
 *    user experience.
 *
 * 2. {@code DelegatingPasswordEncoder} -- demonstrates how Spring Security
 *    handles legacy password formats during a migration.  Passwords prefixed
 *    with {@code {bcrypt}} are verified against BCrypt; a system in transition
 *    might also register {@code {sha256}} or {@code {md5}} for read-only
 *    comparison while forcing a re-encode on next login.
 */
@Configuration
public class PasswordConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public PasswordEncoder delegatingPasswordEncoder() {
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("bcrypt", new BCryptPasswordEncoder(12));

        DelegatingPasswordEncoder delegate = new DelegatingPasswordEncoder("bcrypt", encoders);
        delegate.setDefaultPasswordEncoderForMatches(new BCryptPasswordEncoder(12));
        return delegate;
    }
}
