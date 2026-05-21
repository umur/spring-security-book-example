package com.cinetrack.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ClientCredentialsReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Reactive OAuth2 client configuration.
 *
 * Wires a {@link WebClient} that automatically acquires and attaches access
 * tokens using the {@code client_credentials} grant: suitable for
 * service-to-service calls where there is no end-user involved.
 *
 * The {@link ServerOAuth2AuthorizedClientExchangeFilterFunction} is the
 * reactive equivalent of the servlet-stack
 * {@code ServletOAuth2AuthorizedClientExchangeFilterFunction}. It intercepts
 * each request, checks for a cached token, refreshes if needed, and injects
 * the {@code Authorization: Bearer ...} header: all without blocking.
 *
 * In production the token URI would point to the real authorization server.
 * The in-memory registration here keeps the chapter runnable without external
 * infrastructure.
 */
@Configuration
public class ReactiveOAuth2ClientConfig {

    @Bean
    public ReactiveClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration catalogRegistration = ClientRegistration
                .withRegistrationId("catalog-service")
                .clientId("cinetrack-recommendation")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenUri("https://auth1.cinetrack.io/oauth2/token")
                .scope("catalog:read")
                .build();

        return new InMemoryReactiveClientRegistrationRepository(catalogRegistration);
    }

    @Bean
    public ReactiveOAuth2AuthorizedClientService authorizedClientService(
            ReactiveClientRegistrationRepository registrationRepository) {
        return new InMemoryReactiveOAuth2AuthorizedClientService(registrationRepository);
    }

    @Bean
    public ReactiveOAuth2AuthorizedClientManager authorizedClientManager(
            ReactiveClientRegistrationRepository registrationRepository,
            ReactiveOAuth2AuthorizedClientService authorizedClientService) {

        var manager = new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(
                registrationRepository, authorizedClientService);
        manager.setAuthorizedClientProvider(
                new ClientCredentialsReactiveOAuth2AuthorizedClientProvider());
        return manager;
    }

    /**
     * A {@link WebClient} pre-configured to attach client_credentials tokens.
     *
     * Callers set the client registration id via the exchange attribute:
     * <pre>
     *   catalogClient.get()
     *       .uri("/api/catalog/movies")
     *       .attributes(clientRegistrationId("catalog-service"))
     *       .retrieve()
     *       .bodyToFlux(Movie.class);
     * </pre>
     */
    @Bean
    public WebClient catalogClient(ReactiveOAuth2AuthorizedClientManager authorizedClientManager) {
        ServerOAuth2AuthorizedClientExchangeFilterFunction filter =
                new ServerOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
        filter.setDefaultClientRegistrationId("catalog-service");

        return WebClient.builder()
                .baseUrl("https://catalog.cinetrack.io")
                .filter(filter)
                .build();
    }
}
