package com.cinetrack.catalog;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for CatalogClient.
 *
 * WireMock stands in for both the authorization server (token endpoint) and
 * catalog-service. The client-credentials flow fires on the first request:
 * CatalogClient asks the AS for a token, caches it in memory, then attaches it
 * to every catalog call as a Bearer header. Both legs of that flow are verified.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class CatalogClientTest {

    static WireMockServer wireMock = new WireMockServer(wireMockConfig().dynamicPort());

    @DynamicPropertySource
    static void wireMockProperties(DynamicPropertyRegistry registry) {
        wireMock.start();
        WireMock.configureFor("localhost", wireMock.port());
        registry.add("wiremock.server.port", wireMock::port);
    }

    @Autowired
    private CatalogClient catalogClient;

    @BeforeEach
    void setUp() {
        // ServletOAuth2AuthorizedClientExchangeFilterFunction requires an
        // HttpServletRequest bound to the current thread via RequestContextHolder.
        // In a @SpringBootTest test thread there is no active request, so we bind
        // a mock request manually before each test and clear it afterwards.
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(new MockHttpServletRequest(), new MockHttpServletResponse()));
    }

    @BeforeEach
    void stubTokenEndpoint() {
        // AS returns a token for every client_credentials request
        wireMock.stubFor(post(urlEqualTo("/oauth2/token"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                  "access_token": "test-token",
                                  "token_type": "Bearer",
                                  "expires_in": 3600
                                }
                                """)));
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    @AfterEach
    void resetWireMock() {
        wireMock.resetAll();
    }

    @Test
    void fetchMovies_returnsCatalogMovies() {
        wireMock.stubFor(get(urlPathEqualTo("/api/catalog/movies"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                [
                                  {"id": "1", "title": "Inception",      "genre": "Sci-Fi"},
                                  {"id": "2", "title": "The Dark Knight", "genre": "Action"}
                                ]
                                """)));

        List<Movie> movies = catalogClient.fetchMovies().collectList().block();

        assertThat(movies).hasSize(2);
        assertThat(movies.get(0).title()).isEqualTo("Inception");
        assertThat(movies.get(1).title()).isEqualTo("The Dark Knight");
    }

    @Test
    void fetchMovies_sendsAuthorizationHeader() {
        wireMock.stubFor(get(urlPathEqualTo("/api/catalog/movies"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("[]")));

        catalogClient.fetchMovies().collectList().block();

        // Verify catalog-service received the Bearer token obtained from the AS
        verify(getRequestedFor(urlPathEqualTo("/api/catalog/movies"))
                .withHeader("Authorization", equalTo("Bearer test-token")));
    }
}
