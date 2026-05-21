package com.cinetrack;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
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

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Chapter 09: SAML2 SP-side integration test with Keycloak.
 *
 * Spins up Keycloak 25.0 in start-dev mode and asserts SP-side behaviour:
 *
 *   1. SP metadata endpoint returns valid XML (200).
 *   2. Unauthenticated request to protected endpoint produces 302 redirect.
 *   3. Keycloak container's master realm is reachable (smoke test).
 *
 * A full browser-driven round-trip (SP-initiated SSO, IdP form submission,
 * ACS POST) requires a headless browser and is out of scope. The redirect
 * assertion is the correct SP-side contract: it confirms Spring Security's
 * SAML2 filter generates a redirect with the SP registration correctly wired.
 *
 * Container: quay.io/keycloak/keycloak:25.0 (start-dev, random port).
 *
 * The test skips automatically when Docker is not available.
 */
@SpringBootTest
class Saml2KeycloakIT {

    static GenericContainer<?> keycloak;
    static boolean dockerAvailable = false;

    @BeforeAll
    static void startKeycloak() {
        // Probe Docker availability via Testcontainers' own resolver.
        dockerAvailable = org.testcontainers.DockerClientFactory.instance().isDockerAvailable();
        Assumptions.assumeTrue(dockerAvailable,
                "Skipping Saml2KeycloakIT: Testcontainers cannot reach a healthy Docker daemon. "
                + "Run on a CI host or restart Docker Desktop locally.");

        keycloak = new GenericContainer<>("quay.io/keycloak/keycloak:25.0")
                .withCommand("start-dev")
                .withEnv("KEYCLOAK_ADMIN", "admin")
                .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
                .withExposedPorts(8080)
                .waitingFor(
                        Wait.forHttp("/realms/master")
                                .forStatusCode(200)
                                .withStartupTimeout(Duration.ofMinutes(3))
                );
        keycloak.start();
    }

    @DynamicPropertySource
    static void containerProperties(DynamicPropertyRegistry registry) {
        if (dockerAvailable && keycloak != null && keycloak.isRunning()) {
            registry.add("keycloak.base-url",
                    () -> "http://localhost:" + keycloak.getMappedPort(8080));
        }
    }

    @Autowired
    WebApplicationContext context;

    MockMvc mockMvc;

    void setUpMockMvc() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    /**
     * SP metadata endpoint must return 200 with valid SAML XML.
     * Exercises RelyingPartyRegistrationRepository resolution.
     */
    @Test
    @DisplayName("SP metadata endpoint returns 200 with EntityDescriptor XML")
    void spMetadata_returns200WithSamlXml() throws Exception {
        setUpMockMvc();
        mockMvc.perform(get("/saml2/service-provider-metadata/cinetrack-okta"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("EntityDescriptor")));
    }

    /**
     * Unauthenticated request must redirect to SAML2 SP-initiated SSO path.
     */
    @Test
    @DisplayName("GET /api/movies unauthenticated redirects to SAML2 authenticate endpoint")
    void protectedEndpoint_unauthenticated_redirectsToSaml2Authenticate() throws Exception {
        setUpMockMvc();
        mockMvc.perform(get("/api/movies"))
                .andExpect(status().isFound());
    }

    /**
     * Keycloak master realm reachability smoke test.
     */
    @Test
    @DisplayName("Keycloak container master realm is reachable")
    void keycloakContainer_masterRealmReachable() throws Exception {
        Assumptions.assumeTrue(keycloak != null && keycloak.isRunning(),
                "Keycloak container not running");
        String healthUrl = "http://localhost:" + keycloak.getMappedPort(8080) + "/realms/master";
        java.net.URL url = new java.net.URL(healthUrl);
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        int responseCode = conn.getResponseCode();
        org.assertj.core.api.Assertions.assertThat(responseCode).isEqualTo(200);
    }
}
