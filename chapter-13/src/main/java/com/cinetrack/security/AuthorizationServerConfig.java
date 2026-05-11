package com.cinetrack.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * Chapter 13: Authorization Server configuration.
 *
 * Registers two clients that represent the two most common OAuth2 patterns:
 *   - cinetrack-web: browser app using authorization_code + PKCE (no client secret in the browser)
 *   - catalog-service: backend daemon using client_credentials (machine-to-machine)
 *
 * Order(1) ensures this filter chain is evaluated before the default security chain.
 */
@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .with(authorizationServerConfigurer, authServer ->
                authServer.oidc(oidc -> {}) // enable OpenID Connect 1.0
            )
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());

        return http.build();
    }

    /**
     * Two clients:
     *
     * cinetrack-web — authorization_code + PKCE + refresh_token.
     *   No client secret: public clients (SPAs, mobile apps) cannot keep secrets.
     *   PKCE replaces the secret with a per-request proof key.
     *
     * catalog-service — client_credentials.
     *   Backend service calling another backend; no user involved.
     *   Authenticates with client_id + client_secret over Basic auth.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient cinetrackWeb = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("cinetrack-web")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // PKCE — no secret
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:3000/callback")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("catalog:read")
                .clientSettings(
                    ClientSettings.builder()
                        .requireProofKey(true)           // enforce PKCE
                        .requireAuthorizationConsent(false)
                        .build()
                )
                .build();

        RegisteredClient catalogService = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("catalog-service")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("catalog.internal")
                .build();

        return new InMemoryRegisteredClientRepository(cinetrackWeb, catalogService);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    /**
     * RSA key pair for signing JWTs.
     * In production this comes from a key store or a secrets manager — never generated at startup.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8080")
                .build();
    }

    private static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate RSA key pair", ex);
        }
    }
}
