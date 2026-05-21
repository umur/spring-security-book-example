package com.cinetrack.mfa;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for TotpService.
 *
 * No Spring context is needed; TotpService has no dependencies beyond
 * the java-otp library and the JDK crypto providers.
 */
class TotpServiceTest {

    private final TotpService totpService = new TotpService();

    @Test
    void generateSecret_returnsNonNullNonEmptyString() {
        String secret = totpService.generateSecret();

        assertThat(secret).isNotNull().isNotEmpty();
    }

    @Test
    void isValid_returnsTrueForFreshlyGeneratedCode() {
        String secret = totpService.generateSecret();
        String code = totpService.generateCode(secret);

        assertThat(totpService.isValid(secret, code)).isTrue();
    }

    @Test
    void isValid_returnsFalseForWrongCode() {
        String secret = totpService.generateSecret();

        // "000000" is almost certainly wrong (1-in-1,000,000 chance of collision).
        assertThat(totpService.isValid(secret, "000000")).isFalse();
    }

    @Test
    void isValid_returnsFalseForNullCode() {
        String secret = totpService.generateSecret();

        assertThat(totpService.isValid(secret, null)).isFalse();
    }

    @Test
    void isValid_returnsFalseForNullSecret() {
        assertThat(totpService.isValid(null, "123456")).isFalse();
    }
}
