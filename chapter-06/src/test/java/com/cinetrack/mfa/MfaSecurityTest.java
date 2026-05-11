package com.cinetrack.mfa;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies authority-based access control for the MFA step-up model.
 *
 * The authority model has two independent claims:
 *   FACTOR_PASSWORD  -- the user passed the username/password check.
 *   FACTOR_TOTP      -- the user also passed the TOTP verification step.
 *
 * Sensitive endpoints (e.g. subscription upgrades) require FACTOR_TOTP;
 * standard catalog endpoints require only FACTOR_PASSWORD.
 *
 * Because Spring Boot 4 removed the @WebMvcTest slice, all tests use a full
 * application context with a random port. The MFA flow is driven by logging
 * in via the form-login endpoint (which grants FACTOR_PASSWORD), then calling
 * POST /api/mfa/verify with a live TOTP code (which grants FACTOR_TOTP).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MfaSecurityTest {

    @LocalServerPort
    int port;

    @Autowired
    TotpService totpService;

    RestClient client;

    @BeforeEach
    void setUp() {
        client = RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .build();
    }

    // -----------------------------------------------------------------------
    // /api/movies requires FACTOR_PASSWORD only
    // -----------------------------------------------------------------------

    @Test
    void movies_afterPasswordLogin_returns200() {
        String sessionCookie = loginAsAlice();
        assertThat(sessionCookie).isNotNull();

        ResponseEntity<Void> response = client.get()
                .uri("/api/movies")
                .header("Cookie", sessionCookie)
                .retrieve()
                .onStatus(s -> true, (req, res) -> {})
                .toBodilessEntity();

        assertThat(response.getStatusCode().value())
                .as("/api/movies must be accessible after password login")
                .isEqualTo(200);
    }

    // -----------------------------------------------------------------------
    // /api/subscriptions/upgrade requires FACTOR_TOTP
    // -----------------------------------------------------------------------

    @Test
    void upgrade_withOnlyPasswordFactor_returns403() {
        String sessionCookie = loginAsAlice();
        assertThat(sessionCookie).isNotNull();

        ResponseEntity<Void> response = client.put()
                .uri("/api/subscriptions/upgrade")
                .header("Cookie", sessionCookie)
                .retrieve()
                .onStatus(s -> true, (req, res) -> {})
                .toBodilessEntity();

        assertThat(response.getStatusCode().value())
                .as("/api/subscriptions/upgrade must require FACTOR_TOTP")
                .isEqualTo(403);
    }

    @Test
    void upgrade_afterTotpVerification_returns200() {
        String sessionCookie = loginAsAlice();
        assertThat(sessionCookie).isNotNull();

        // Generate a live TOTP code for Alice's known test secret.
        String code = totpService.generateCode(MfaUserDetailsService.ALICE_TOTP_SECRET);

        // POST /api/mfa/verify with the TOTP code to elevate to FACTOR_TOTP.
        ResponseEntity<Void> verifyResponse = client.post()
                .uri("/api/mfa/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Cookie", sessionCookie)
                .body("{\"code\":\"" + code + "\"}")
                .retrieve()
                .onStatus(s -> true, (req, res) -> {})
                .toBodilessEntity();

        assertThat(verifyResponse.getStatusCode().value())
                .as("TOTP verification must succeed")
                .isEqualTo(200);

        // The session cookie may be refreshed; use the latest one.
        List<String> setCookie = verifyResponse.getHeaders().get("Set-Cookie");
        if (setCookie != null) {
            String newSession = extractCookieValue(setCookie, "JSESSIONID");
            if (newSession != null) {
                sessionCookie = "JSESSIONID=" + newSession;
            }
        }

        // Now /api/subscriptions/upgrade must return 200.
        ResponseEntity<Void> upgradeResponse = client.put()
                .uri("/api/subscriptions/upgrade")
                .header("Cookie", sessionCookie)
                .retrieve()
                .onStatus(s -> true, (req, res) -> {})
                .toBodilessEntity();

        assertThat(upgradeResponse.getStatusCode().value())
                .as("/api/subscriptions/upgrade must be accessible after TOTP verification")
                .isEqualTo(200);
    }

    // -----------------------------------------------------------------------
    // Unauthenticated access is rejected
    // -----------------------------------------------------------------------

    @Test
    void movies_withNoAuthentication_isRejected() {
        ResponseEntity<Void> response = client.get()
                .uri("/api/movies")
                .retrieve()
                .onStatus(s -> true, (req, res) -> {})
                .toBodilessEntity();

        assertThat(response.getStatusCode().value())
                .as("Unauthenticated access must be rejected (401 or 302)")
                .isNotEqualTo(200);
    }

    // -----------------------------------------------------------------------
    // Utilities
    // -----------------------------------------------------------------------

    /**
     * Logs in as alice via form login (CSRF is disabled in ch-06 SecurityConfig)
     * and returns the JSESSIONID cookie string.
     */
    private String loginAsAlice() {
        ResponseEntity<Void> response = client.post()
                .uri("/login")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("username=alice&password=password")
                .retrieve()
                .onStatus(s -> true, (req, res) -> {})
                .toBodilessEntity();

        List<String> cookies = response.getHeaders().get("Set-Cookie");
        if (cookies == null) return null;
        String sessionId = extractCookieValue(cookies, "JSESSIONID");
        return sessionId != null ? "JSESSIONID=" + sessionId : null;
    }

    private String extractCookieValue(List<String> setCookieHeaders, String name) {
        if (setCookieHeaders == null) return null;
        for (String header : setCookieHeaders) {
            for (String part : header.split(";")) {
                part = part.trim();
                if (part.startsWith(name + "=")) {
                    return part.substring(name.length() + 1);
                }
            }
        }
        return null;
    }
}
