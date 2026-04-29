package com.example.security.microservice.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * Configures the OAuth2 client infrastructure for the client_credentials flow.
 *
 * <p>Uses {@link AuthorizedClientServiceOAuth2AuthorizedClientManager} which operates
 * outside of an HTTP request context — required for service-to-service calls where
 * there is no user session or servlet request in scope.</p>
 *
 * <p>Token acquisition and Bearer-header attachment is handled explicitly in
 * {@link com.example.security.microservice.service.ExternalServiceClient} using the
 * manager exposed here, keeping the config free of WebFlux / reactive dependencies.</p>
 */
@Configuration
@EnableConfigurationProperties(ExternalServiceProperties.class)
public class OAuth2ClientConfig {

    /**
     * An {@link OAuth2AuthorizedClientManager} that works outside of an HTTP request
     * context, required for service-to-service (client_credentials) flows where there
     * is no user session.
     */
    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientService authorizedClientService) {

        var provider = OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials()
                .build();

        var manager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                clientRegistrationRepository, authorizedClientService);
        manager.setAuthorizedClientProvider(provider);
        return manager;
    }
}
