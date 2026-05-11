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
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import java.util.function.Function;

/**
 * Chapter 15: Authorization Server with customized UserInfo endpoint.
 *
 * The UserInfo response is enriched with a "subscription_tier" claim so that
 * resource servers can make authorization decisions without a second lookup.
 *
 * Order(1) ensures this chain handles all authorization server endpoints
 * before the application's OAuth2 login chain (Order 2) is consulted.
 */
@Configuration
@Order(1)
public class AuthorizationServerConfig {

    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .with(authorizationServerConfigurer, authServer ->
                authServer.oidc(oidc ->
                    oidc.userInfoEndpoint(userInfo ->
                        userInfo.userInfoMapper(userInfoMapper())
                    )
                )
            )
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());

        return http.build();
    }

    /**
     * Maps the authentication context to an OidcUserInfo response.
     *
     * subscription_tier is appended here. In production it would be fetched
     * from the subscription-service; for the book example it is hardcoded.
     */
    private Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper() {
        return context -> {
            OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
            Jwt jwt = (Jwt) authentication.getPrincipal();

            return OidcUserInfo.builder()
                    .subject(jwt.getSubject())
                    .claim("email", jwt.getClaim("email"))
                    .claim("name", jwt.getClaim("name"))
                    .claim("subscription_tier", "PREMIUM")
                    .build();
        };
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient cinetrackWeb = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("cinetrack-web")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:3000/callback")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("catalog:read")
                .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(cinetrackWeb);
    }

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
