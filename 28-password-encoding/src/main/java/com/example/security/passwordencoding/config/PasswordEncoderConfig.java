package com.example.security.passwordencoding.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;

/**
 * Exposes individual password encoder beans so they can be injected into the
 * controller for demonstration purposes, plus a primary DelegatingPasswordEncoder
 * used throughout the application.
 *
 * <p>DelegatingPasswordEncoder stores a prefix such as {bcrypt}, {argon2}, {pbkdf2},
 * or {scrypt} alongside the encoded hash. When matching, it reads the prefix and
 * delegates to the appropriate encoder. This enables seamless algorithm migration:
 * you can change the default encoder and existing hashes still verify correctly
 * because the prefix identifies which encoder to use.</p>
 */
@Configuration
public class PasswordEncoderConfig {

    @Bean
    public BCryptPasswordEncoder bcryptPasswordEncoder() {
        // strength 12 is the recommended minimum for production
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public Argon2PasswordEncoder argon2PasswordEncoder() {
        // saltLength=16, hashLength=32, parallelism=1, memory=65536, iterations=3
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    @Bean
    public Pbkdf2PasswordEncoder pbkdf2PasswordEncoder() {
        return Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    @Bean
    public SCryptPasswordEncoder scryptPasswordEncoder() {
        return SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    /**
     * Primary encoder used by Spring Security for storing and verifying user passwords.
     * Uses bcrypt as the default encoding algorithm but can verify passwords encoded
     * with any of the supported algorithms via the {prefix} mechanism.
     */
    @Bean
    @Primary
    public PasswordEncoder passwordEncoder() {
        String encodingId = "bcrypt";
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("bcrypt", bcryptPasswordEncoder());
        encoders.put("argon2", argon2PasswordEncoder());
        encoders.put("pbkdf2", pbkdf2PasswordEncoder());
        encoders.put("scrypt", scryptPasswordEncoder());
        // Legacy noop kept so old plain-text passwords can still be validated during migration
        encoders.put("noop", org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance());
        return new DelegatingPasswordEncoder(encodingId, encoders);
    }
}
