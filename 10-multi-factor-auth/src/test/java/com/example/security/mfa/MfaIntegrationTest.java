package com.example.security.mfa;

import com.example.security.mfa.controller.AuthController.LoginResponse;
import com.example.security.mfa.controller.AuthController.VerifyMfaResponse;
import com.example.security.mfa.model.AppUser;
import com.example.security.mfa.repository.AppUserRepository;
import com.example.security.mfa.security.SessionTokenFilter;
import com.example.security.mfa.service.MfaService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
class MfaIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17-alpine");

    @DynamicPropertySource
    static void configureDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
    }

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private AppUserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private MfaService mfaService;

    @Nested
    @DisplayName("Full MFA flow")
    class FullMfaFlow {

        @Test
        @DisplayName("setup MFA -> login -> verify TOTP -> access protected resource")
        void fullMfaSetupLoginVerifyFlow() {
            // Create a fresh user for this test
            AppUser testUser = userRepository.save(AppUser.builder()
                    .username("integrationmfauser")
                    .password(passwordEncoder.encode("testpass"))
                    .role("USER")
                    .mfaEnabled(false)
                    .build());

            // Setup MFA
            var setup = mfaService.setupMfa("integrationmfauser");
            assertThat(setup.secret()).isNotBlank();
            assertThat(setup.qrCodeUrl()).contains("otpauth://totp/");

            // Login - should require MFA
            var loginHeaders = new HttpHeaders();
            loginHeaders.setContentType(MediaType.APPLICATION_JSON);
            var loginBody = Map.of("username", "integrationmfauser", "password", "testpass");
            var loginResponse = restTemplate.exchange(
                    "/api/auth/login",
                    HttpMethod.POST,
                    new HttpEntity<>(loginBody, loginHeaders),
                    LoginResponse.class
            );

            assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(loginResponse.getBody()).isNotNull();
            assertThat(loginResponse.getBody().mfaRequired()).isTrue();
            String tempToken = loginResponse.getBody().tempToken();
            assertThat(tempToken).isNotBlank();

            // Verify TOTP
            int validCode = generateCurrentTotp(setup.secret());
            var verifyHeaders = new HttpHeaders();
            verifyHeaders.setContentType(MediaType.APPLICATION_JSON);
            var verifyBody = Map.of("tempToken", tempToken, "totpCode", validCode);
            var verifyResponse = restTemplate.exchange(
                    "/api/auth/verify-mfa",
                    HttpMethod.POST,
                    new HttpEntity<>(verifyBody, verifyHeaders),
                    VerifyMfaResponse.class
            );

            assertThat(verifyResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(verifyResponse.getBody()).isNotNull();
            String sessionToken = verifyResponse.getBody().sessionToken();
            assertThat(sessionToken).isNotBlank();

            // Access protected resource with session token
            var protectedHeaders = new HttpHeaders();
            protectedHeaders.set(SessionTokenFilter.SESSION_TOKEN_HEADER, sessionToken);
            var protectedResponse = restTemplate.exchange(
                    "/api/protected",
                    HttpMethod.GET,
                    new HttpEntity<>(protectedHeaders),
                    String.class
            );

            assertThat(protectedResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(protectedResponse.getBody()).contains("Access granted");
        }

        @Test
        @DisplayName("wrong TOTP code -> 401")
        void wrongTotpCodeReturns401() {
            userRepository.findByUsername("wrongtotpuser").ifPresent(userRepository::delete);
            userRepository.save(AppUser.builder()
                    .username("wrongtotpuser")
                    .password(passwordEncoder.encode("testpass"))
                    .role("USER")
                    .mfaEnabled(false)
                    .build());
            mfaService.setupMfa("wrongtotpuser");

            var loginHeaders = new HttpHeaders();
            loginHeaders.setContentType(MediaType.APPLICATION_JSON);
            var loginBody = Map.of("username", "wrongtotpuser", "password", "testpass");
            var loginResponse = restTemplate.exchange(
                    "/api/auth/login",
                    HttpMethod.POST,
                    new HttpEntity<>(loginBody, loginHeaders),
                    LoginResponse.class
            );

            String tempToken = loginResponse.getBody().tempToken();

            var verifyHeaders = new HttpHeaders();
            verifyHeaders.setContentType(MediaType.APPLICATION_JSON);
            var verifyBody = Map.of("tempToken", tempToken, "totpCode", 000000);
            var verifyResponse = restTemplate.exchange(
                    "/api/auth/verify-mfa",
                    HttpMethod.POST,
                    new HttpEntity<>(verifyBody, verifyHeaders),
                    String.class
            );

            assertThat(verifyResponse.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    @Nested
    @DisplayName("Non-MFA user direct login")
    class NonMfaUserFlow {

        @Test
        @DisplayName("non-MFA user login -> direct session token -> access protected")
        void nonMfaUserDirectLoginFlow() {
            userRepository.findByUsername("directloginuser").ifPresent(userRepository::delete);
            userRepository.save(AppUser.builder()
                    .username("directloginuser")
                    .password(passwordEncoder.encode("testpass"))
                    .role("USER")
                    .mfaEnabled(false)
                    .build());

            var loginHeaders = new HttpHeaders();
            loginHeaders.setContentType(MediaType.APPLICATION_JSON);
            var loginBody = Map.of("username", "directloginuser", "password", "testpass");
            var loginResponse = restTemplate.exchange(
                    "/api/auth/login",
                    HttpMethod.POST,
                    new HttpEntity<>(loginBody, loginHeaders),
                    LoginResponse.class
            );

            assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(loginResponse.getBody().mfaRequired()).isFalse();
            String sessionToken = loginResponse.getBody().sessionToken();
            assertThat(sessionToken).isNotBlank();

            var protectedHeaders = new HttpHeaders();
            protectedHeaders.set(SessionTokenFilter.SESSION_TOKEN_HEADER, sessionToken);
            var protectedResponse = restTemplate.exchange(
                    "/api/protected",
                    HttpMethod.GET,
                    new HttpEntity<>(protectedHeaders),
                    String.class
            );

            assertThat(protectedResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(protectedResponse.getBody()).contains("Access granted");
        }

        @Test
        @DisplayName("unauthenticated request to protected -> 401")
        void unauthenticatedProtectedReturns401() {
            var response = restTemplate.getForEntity("/api/protected", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    private int generateCurrentTotp(String secret) {
        long timeStep = System.currentTimeMillis() / 1000 / 30;
        return generateCode(secret, timeStep);
    }

    private int generateCode(String secret, long timeStep) {
        try {
            byte[] key = java.util.Base64.getDecoder().decode(secret);
            byte[] msg = longToBytes(timeStep);
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA1");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(msg);
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);
            return binary % 1_000_000;
        } catch (Exception e) {
            throw new RuntimeException(e);
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
}
