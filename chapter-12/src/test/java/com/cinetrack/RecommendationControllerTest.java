package com.cinetrack;

import com.cinetrack.recommendation.RecommendationController;
import com.cinetrack.security.SecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Login;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Slice test for RecommendationController authorization rules.
 *
 * Two scenarios are verified:
 *   1. Unauthenticated requests → redirect to OAuth2 login (302 to /oauth2/authorization/...)
 *   2. Authenticated users (via oauth2Login() mock) → pass the filter chain and reach the controller
 *
 * RecommendationController is declared as a @MockBean so it is registered as a
 * Spring MVC handler (satisfying the @WebMvcTest slice) while its recommend() method
 * returns an empty list without invoking the real WebClient chain. This isolates the
 * security filter chain behavior from catalog-service connectivity.
 */
@WebMvcTest(RecommendationController.class)
@Import({SecurityConfig.class, RecommendationControllerTest.TestConfig.class})
class RecommendationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private RecommendationController recommendationController;

    @Configuration
    static class TestConfig {

        @Bean
        public ClientRegistrationRepository clientRegistrationRepository() {
            ClientRegistration registration = ClientRegistration
                    .withRegistrationId("catalog-cc")
                    .clientId("recommendation-service")
                    .clientSecret("secret")
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .tokenUri("http://localhost:9000/oauth2/token")
                    .build();

            ClientRegistration loginRegistration = ClientRegistration
                    .withRegistrationId("cinetrack-login")
                    .clientId("recommendation-web")
                    .clientSecret("web-secret")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                    .authorizationUri("http://localhost:9000/oauth2/authorize")
                    .tokenUri("http://localhost:9000/oauth2/token")
                    .userInfoUri("http://localhost:9000/userinfo")
                    .userNameAttributeName("sub")
                    .scope("openid", "profile", "email")
                    .build();

            return new InMemoryClientRegistrationRepository(registration, loginRegistration);
        }

        @Bean
        public WebClient catalogClient() {
            // Placeholder bean satisfying CatalogClient's constructor dependency.
            // The real WebClient is never called because RecommendationController
            // is a @MockBean whose recommend() returns an empty list.
            return mock(WebClient.class);
        }
    }

    @Test
    void unauthenticated_redirectsToOAuth2Login() throws Exception {
        // Spring Security redirects to /oauth2/authorization/<registrationId> for
        // unauthenticated requests when oauth2Login() is configured.
        mockMvc.perform(get("/api/recommendations"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void authenticatedUser_passes() throws Exception {
        // oauth2Login() injects a fully authenticated OAuth2AuthenticationToken
        // into the security context, simulating a user who has completed the
        // authorization code flow.
        when(recommendationController.recommend()).thenReturn(List.of());

        mockMvc.perform(get("/api/recommendations")
                        .with(oauth2Login()))
                .andExpect(status().isOk());
    }
}
