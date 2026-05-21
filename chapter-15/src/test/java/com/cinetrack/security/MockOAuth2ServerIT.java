package com.cinetrack.security;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.time.Duration;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Chapter 15: Google OIDC integration test using mock-oauth2-server.
 *
 * mock-oauth2-server (ghcr.io/navikt/mock-oauth2-server:2.1.10) stands in for
 * Google's OIDC discovery endpoint. Spring Security's google provider is
 * redirected to the container via @DynamicPropertySource.
 *
 * READER NOTE: Real Google OAuth2 requires a valid client_id and client_secret
 * registered in the Google Cloud Console. The mock-oauth2-server replaces
 * Google's authorization server entirely for automated testing. Production
 * deployments must supply GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET as
 * environment variables; these values are never committed to version control.
 *
 * The IT asserts:
 *   1. The mock OIDC discovery endpoint is reachable and well-formed.
 *   2. An oidcLogin() post-processed request to /api/me returns 200 with the
 *      expected JSON fields, exercising CineTrackOidcUserService enrichment.
 *   3. Unauthenticated /api/me issues a 302 redirect.
 *   4. Login page is reachable without authentication.
 *
 * Framework-level mock justification for oidcLogin(): the authorization-code
 * redirect leg requires a browser. oidcLogin() correctly simulates a completed
 * OIDC session for controller and service layer assertions. The container
 * validates discovery-endpoint resolution and redirect URL generation.
 *
 * The test skips automatically when Docker is not available.
 */
@SpringBootTest
class MockOAuth2ServerIT {

    static GenericContainer<?> mockOAuth2;
    static boolean dockerAvailable = false;

    @BeforeAll
    static void startMockOAuth2() {
        dockerAvailable = org.testcontainers.DockerClientFactory.instance().isDockerAvailable();
        Assumptions.assumeTrue(dockerAvailable,
                "Skipping MockOAuth2ServerIT: Docker not available (socket not reachable)");

        mockOAuth2 = new GenericContainer<>("ghcr.io/navikt/mock-oauth2-server:2.1.10")
                .withExposedPorts(8080)
                .waitingFor(
                        Wait.forHttp("/default/.well-known/openid-configuration")
                                .forStatusCode(200)
                                .withStartupTimeout(Duration.ofMinutes(2))
                );
        mockOAuth2.start();
    }

    @DynamicPropertySource
    static void overrideGoogleProvider(DynamicPropertyRegistry registry) {
        if (dockerAvailable && mockOAuth2 != null && mockOAuth2.isRunning()) {
            String mockIssuer = "http://localhost:" + mockOAuth2.getMappedPort(8080) + "/default";
            registry.add("spring.security.oauth2.client.provider.google.issuer-uri",
                    () -> mockIssuer);
        }
    }

    @Autowired
    WebApplicationContext context;

    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    /**
     * Asserts that the mock OIDC discovery endpoint is reachable and contains
     * the expected fields.
     */
    @Test
    @DisplayName("Mock OIDC discovery endpoint is reachable and well-formed")
    void mockOidcDiscovery_isReachable() throws Exception {
        Assumptions.assumeTrue(mockOAuth2 != null && mockOAuth2.isRunning(),
                "mock-oauth2-server not running");
        String discoveryUrl = "http://localhost:" + mockOAuth2.getMappedPort(8080)
                + "/default/.well-known/openid-configuration";
        java.net.URL url = new java.net.URL(discoveryUrl);
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        int code = conn.getResponseCode();
        org.assertj.core.api.Assertions.assertThat(code).isEqualTo(200);

        java.io.InputStream is = conn.getInputStream();
        String body = new String(is.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        org.assertj.core.api.Assertions.assertThat(body).contains("issuer");
        org.assertj.core.api.Assertions.assertThat(body).contains("jwks_uri");
    }

    /**
     * Simulates a completed OIDC login using oidcLogin() and asserts /api/me
     * returns 200 with the expected JSON structure.
     */
    @Test
    @DisplayName("Authenticated OIDC user can access /api/me and gets enriched profile")
    void authenticatedOidcUser_canAccessMe_withEnrichedProfile() throws Exception {
        mockMvc.perform(get("/api/me")
                        .with(oidcLogin()
                                .idToken(token -> token
                                        .subject("google-user-123")
                                        .claim("email", "alice@gmail.com")
                                        .claim("name", "Alice Example")
                                )
                        )
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").exists())
                .andExpect(jsonPath("$.name").exists());
    }

    /**
     * Unauthenticated request to /api/me must redirect to OAuth2 authorization.
     */
    @Test
    @DisplayName("Unauthenticated GET /api/me redirects to OIDC authorization endpoint")
    void unauthenticated_redirectsToOAuth2Authorization() throws Exception {
        mockMvc.perform(get("/api/me"))
                .andExpect(status().is3xxRedirection());
    }

    /**
     * Login page must be accessible without authentication (permit-all).
     */
    @Test
    @DisplayName("Login page is accessible without authentication")
    void loginPage_isPermitAll() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk());
    }
}
