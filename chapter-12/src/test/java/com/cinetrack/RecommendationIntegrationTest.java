package com.cinetrack;

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

import com.cinetrack.recommendation.CatalogMovie;
import com.cinetrack.recommendation.Recommendation;
import com.cinetrack.recommendation.RecommendationController;

import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for the full RecommendationController flow.
 *
 * WireMock stubs both the token endpoint and the catalog endpoint.
 * We call the controller bean directly (bypassing HTTP security) to exercise
 * the RecommendationController.recommend() method, CatalogMovie, and Recommendation
 * record constructors and accessors.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class RecommendationIntegrationTest {

    static WireMockServer wireMock = new WireMockServer(wireMockConfig().dynamicPort());

    @DynamicPropertySource
    static void wireMockProperties(DynamicPropertyRegistry registry) {
        wireMock.start();
        WireMock.configureFor("localhost", wireMock.port());
        registry.add("wiremock.server.port", wireMock::port);
    }

    @Autowired
    RecommendationController recommendationController;

    @BeforeEach
    void setUp() {
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(new MockHttpServletRequest(), new MockHttpServletResponse()));

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
        wireMock.resetAll();
    }

    @Test
    void recommend_returnsMappedRecommendations() {
        wireMock.stubFor(get(urlPathEqualTo("/api/catalog/movies"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                [
                                  {"id": 1, "title": "Inception", "year": 2010},
                                  {"id": 2, "title": "Interstellar", "year": 2014}
                                ]
                                """)));

        List<Recommendation> recs = recommendationController.recommend();

        assertThat(recs).hasSize(2);
        assertThat(recs.get(0).movieId()).isEqualTo(1L);
        assertThat(recs.get(0).title()).isEqualTo("Inception");
        assertThat(recs.get(0).year()).isEqualTo(2010);
        assertThat(recs.get(0).reason()).isEqualTo("Trending this week");
        assertThat(recs.get(1).title()).isEqualTo("Interstellar");
    }

    @Test
    void recommend_emptyCatalog_returnsEmptyList() {
        wireMock.stubFor(get(urlPathEqualTo("/api/catalog/movies"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("[]")));

        List<Recommendation> recs = recommendationController.recommend();

        assertThat(recs).isEmpty();
    }

    @Test
    void catalogMovie_record_accessors() {
        CatalogMovie cm = new CatalogMovie(5L, "Parasite", 2019);
        assertThat(cm.id()).isEqualTo(5L);
        assertThat(cm.title()).isEqualTo("Parasite");
        assertThat(cm.year()).isEqualTo(2019);
    }

    @Test
    void recommendation_record_accessors() {
        Recommendation r = new Recommendation(3L, "The Dark Knight", 2008, "Classic");
        assertThat(r.movieId()).isEqualTo(3L);
        assertThat(r.title()).isEqualTo("The Dark Knight");
        assertThat(r.year()).isEqualTo(2008);
        assertThat(r.reason()).isEqualTo("Classic");
    }
}
