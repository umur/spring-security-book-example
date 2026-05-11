package com.cinetrack.mfa;

import java.util.Set;

/**
 * In-memory user representation for the MFA demo.
 *
 * {@code totpSecret} is null for users who have not enrolled in TOTP.
 * {@code roles} contains simple role strings (e.g. "USER", "ADMIN");
 * granted authorities are derived from these in MfaUserDetailsService.
 */
public record MfaUser(
        String username,
        String password,
        String totpSecret,
        Set<String> roles
) {}
