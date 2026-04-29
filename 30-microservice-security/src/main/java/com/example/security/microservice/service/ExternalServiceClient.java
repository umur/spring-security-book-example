package com.example.security.microservice.service;

import com.example.security.microservice.config.ExternalServiceProperties;
import com.example.security.microservice.dto.AggregatedResponse.ExternalData;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

/**
 * Wraps all outgoing OAuth2-authenticated calls to the external service.
 * Obtains a token via client_credentials grant using {@link OAuth2AuthorizedClientManager},
 * then attaches it as a Bearer token on each request.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ExternalServiceClient {

    private static final String CLIENT_REGISTRATION_ID = "external-service";

    private final OAuth2AuthorizedClientManager authorizedClientManager;
    private final ExternalServiceProperties externalServiceProperties;

    /**
     * Fetches data from the external service, attaching a client_credentials token.
     * Returns {@link ExternalData} containing the source service name and item list.
     */
    public ExternalData fetchExternalData() {
        String token = obtainAccessToken();

        RestClient restClient = RestClient.builder()
                .baseUrl(externalServiceProperties.baseUrl())
                .build();

        log.debug("Calling external service at {}{}", externalServiceProperties.baseUrl(),
                externalServiceProperties.dataPath());

        @SuppressWarnings("unchecked")
        Map<String, Object> body = restClient.get()
                .uri(externalServiceProperties.dataPath())
                .header("Authorization", "Bearer " + token)
                .retrieve()
                .body(Map.class);

        List<String> items = body != null && body.containsKey("items")
                ? (List<String>) body.get("items")
                : List.of();

        String source = body != null && body.containsKey("service")
                ? (String) body.get("service")
                : "external-service";

        return new ExternalData(source, items);
    }

    private String obtainAccessToken() {
        var authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId(CLIENT_REGISTRATION_ID)
                .principal("microservice-security-app")
                .build();

        var authorizedClient = authorizedClientManager.authorize(authorizeRequest);
        if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
            throw new IllegalStateException(
                    "Could not obtain access token for client registration: " + CLIENT_REGISTRATION_ID);
        }

        return authorizedClient.getAccessToken().getTokenValue();
    }
}
