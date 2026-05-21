package com.cinetrack.auth;

import com.cinetrack.security.AuthorizationServerConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Chapter 13: Verifies that client registrations are wired with the correct settings.
 *
 * These are unit-style assertions against the bean graph: no HTTP calls needed.
 * They catch configuration drift early, before the discovery document or token
 * endpoint tests even run.
 */
@SpringBootTest
class ClientRegistrationTest {

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    /**
     * cinetrack-web is a public client (SPA): it must use PKCE
     * because it cannot safely store a client secret in the browser.
     */
    @Test
    void cinetrackWeb_requiresPkce() {
        RegisteredClient client = registeredClientRepository.findByClientId("cinetrack-web");

        assertThat(client).isNotNull();
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
    }

    /**
     * catalog-service is a confidential backend client.
     * It should only hold the CLIENT_CREDENTIALS grant: granting it
     * AUTHORIZATION_CODE would expose a user-facing flow it should never use.
     */
    @Test
    void catalogService_hasOnlyClientCredentialsGrant() {
        RegisteredClient client = registeredClientRepository.findByClientId("catalog-service");

        assertThat(client).isNotNull();
        assertThat(client.getAuthorizationGrantTypes())
                .containsExactly(AuthorizationGrantType.CLIENT_CREDENTIALS);
    }
}
