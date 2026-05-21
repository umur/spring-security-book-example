package com.cinetrack.authserver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.UUID;

/**
 * Chapter 16: Client registrations for the two advanced OAuth2 flows.
 *
 * cinetrack-tv: Device Authorization Grant (RFC 8628).
 *   TV/console clients cannot open a browser. The device displays a short
 *   user_code; the user approves on their phone. Authenticates with
 *   client_id + client_secret over Basic auth (the TV app can store a secret).
 *
 * cinetrack-web: Authorization Code + PKCE + PAR (RFC 9126).
 *   Browser SPA: cannot store a client secret (public client).
 *   PAR lets it push authorization parameters server-side before the redirect,
 *   protecting them from tampering and keeping them out of browser history.
 */
@Configuration
public class DeviceGrantConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient cinetrackTv = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("cinetrack-tv")
                .clientSecret("{noop}tv-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope(OidcScopes.OPENID)
                .scope("catalog:read")
                .build();

        RegisteredClient cinetrackWeb = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("cinetrack-web")
                .clientSecret("{noop}web-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:3000/callback")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("catalog:read")
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(cinetrackTv, cinetrackWeb);
    }
}
