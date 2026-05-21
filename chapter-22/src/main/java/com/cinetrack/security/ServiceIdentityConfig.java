package com.cinetrack.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Configures the outbound {@link WebClient} used when this service needs to
 * call upstream services in the CineTrack mesh.
 *
 * The {@link ServletOAuth2AuthorizedClientExchangeFilterFunction} filter
 * intercepts every outbound request and automatically:
 * <ol>
 *   <li>Looks up the client registration for {@code recommendation-service}.</li>
 *   <li>Performs the client-credentials token exchange with the authorization
 *       server if no valid token is cached.</li>
 *   <li>Injects {@code Authorization: Bearer <token>} into the request.</li>
 * </ol>
 *
 * Zero-trust principle: every outbound call carries a proof of identity even
 * when both services run inside the same private network segment.
 */
@Configuration
public class ServiceIdentityConfig {

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientService authorizedClientService) {

        AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
            new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                clientRegistrationRepository,
                authorizedClientService
            );

        manager.setAuthorizedClientProvider(
            OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials()
                .build()
        );

        return manager;
    }

    @Bean
    public WebClient serviceWebClient(OAuth2AuthorizedClientManager authorizedClientManager) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
            new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);

        // Default client registration to use for outbound calls.
        // Individual call sites can override with attributes(...) if needed.
        oauth2.setDefaultClientRegistrationId("recommendation-service");

        return WebClient.builder()
                .filter(oauth2)
                .build();
    }
}
