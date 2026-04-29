package com.example.security.mfa;

import com.example.security.mfa.model.AppUser;
import com.example.security.mfa.repository.AppUserRepository;
import com.example.security.mfa.security.SessionTokenFilter;
import com.example.security.mfa.service.AuthService;
import com.example.security.mfa.service.MfaService;
import com.example.security.mfa.service.TotpService;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class MfaSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AppUserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private MfaService mfaService;

    @Autowired
    private TotpService totpService;

    @Autowired
    private AuthService authService;

    private AppUser mfaUser;
    private AppUser plainUser;
    private String mfaUserSecret;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();

        mfaUser = userRepository.save(AppUser.builder()
                .username("mfatestuser")
                .password(passwordEncoder.encode("password"))
                .role("USER")
                .mfaEnabled(false)
                .build());
        var setup = mfaService.setupMfa("mfatestuser");
        mfaUserSecret = setup.secret();
        mfaUser = userRepository.findByUsername("mfatestuser").orElseThrow();

        plainUser = userRepository.save(AppUser.builder()
                .username("plaintestuser")
                .password(passwordEncoder.encode("password"))
                .role("USER")
                .mfaEnabled(false)
                .build());
    }

    @Nested
    @DisplayName("Login endpoint")
    class LoginEndpoint {

        @Test
        @DisplayName("valid credentials with MFA enabled -> mfaRequired=true and tempToken returned")
        void mfaEnabledUserLoginReturnsTempToken() throws Exception {
            var body = Map.of("username", "mfatestuser", "password", "password");

            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(body)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.mfaRequired").value(true))
                    .andExpect(jsonPath("$.tempToken", notNullValue()))
                    .andExpect(jsonPath("$.sessionToken").isEmpty());
        }

        @Test
        @DisplayName("valid credentials without MFA -> mfaRequired=false and sessionToken returned")
        void nonMfaUserLoginReturnsSessionToken() throws Exception {
            var body = Map.of("username", "plaintestuser", "password", "password");

            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(body)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.mfaRequired").value(false))
                    .andExpect(jsonPath("$.sessionToken", notNullValue()));
        }

        @Test
        @DisplayName("invalid credentials -> 401")
        void invalidCredentialsReturn401() throws Exception {
            var body = Map.of("username", "mfatestuser", "password", "wrongpassword");

            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(body)))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("MFA verification endpoint")
    class MfaVerificationEndpoint {

        @Test
        @DisplayName("correct TOTP code -> 200 with sessionToken")
        void correctTotpCodeReturnsSessionToken() throws Exception {
            // Step 1: login to get tempToken
            var loginBody = Map.of("username", "mfatestuser", "password", "password");
            var loginResult = mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(loginBody)))
                    .andExpect(status().isOk())
                    .andReturn();

            String responseBody = loginResult.getResponse().getContentAsString();
            String tempToken = objectMapper.readTree(responseBody).get("tempToken").asText();

            // Step 2: generate valid TOTP code and verify
            int validCode = generateCurrentTotp(mfaUserSecret);
            var verifyBody = Map.of("tempToken", tempToken, "totpCode", validCode);

            mockMvc.perform(post("/api/auth/verify-mfa")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(verifyBody)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.sessionToken", notNullValue()));
        }

        @Test
        @DisplayName("wrong TOTP code -> 401")
        void wrongTotpCodeReturns401() throws Exception {
            var loginBody = Map.of("username", "mfatestuser", "password", "password");
            var loginResult = mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(loginBody)))
                    .andExpect(status().isOk())
                    .andReturn();

            String responseBody = loginResult.getResponse().getContentAsString();
            String tempToken = objectMapper.readTree(responseBody).get("tempToken").asText();

            var verifyBody = Map.of("tempToken", tempToken, "totpCode", 999999);

            mockMvc.perform(post("/api/auth/verify-mfa")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(verifyBody)))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("invalid temp token -> 401")
        void invalidTempTokenReturns401() throws Exception {
            var verifyBody = Map.of("tempToken", "tmp-does-not-exist", "totpCode", 123456);

            mockMvc.perform(post("/api/auth/verify-mfa")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(verifyBody)))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("Protected endpoint")
    class ProtectedEndpoint {

        @Test
        @DisplayName("no auth -> 401")
        void noAuthReturns401() throws Exception {
            mockMvc.perform(get("/api/protected"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("with valid session token -> 200")
        void validSessionTokenReturns200() throws Exception {
            // Login non-MFA user to get session token
            var loginBody = Map.of("username", "plaintestuser", "password", "password");
            var loginResult = mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(loginBody)))
                    .andExpect(status().isOk())
                    .andReturn();

            String responseBody = loginResult.getResponse().getContentAsString();
            String sessionToken = objectMapper.readTree(responseBody).get("sessionToken").asText();

            mockMvc.perform(get("/api/protected")
                            .header(SessionTokenFilter.SESSION_TOKEN_HEADER, sessionToken))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Access granted"));
        }

        @Test
        @DisplayName("with user post-processor -> 200")
        void withUserPostProcessorReturns200() throws Exception {
            mockMvc.perform(get("/api/protected")
                            .with(user("testuser").roles("USER")))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("MFA setup endpoint")
    class MfaSetupEndpoint {

        @Test
        @DisplayName("authenticated user can setup MFA -> returns secret and QR URL")
        void authenticatedUserCanSetupMfa() throws Exception {
            mockMvc.perform(post("/api/auth/mfa/setup")
                            .with(user("plaintestuser").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.secret", notNullValue()))
                    .andExpect(jsonPath("$.qrCodeUrl", notNullValue()));
        }

        @Test
        @DisplayName("unauthenticated user cannot setup MFA -> 401")
        void unauthenticatedCannotSetupMfa() throws Exception {
            mockMvc.perform(post("/api/auth/mfa/setup"))
                    .andExpect(status().isUnauthorized());
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
