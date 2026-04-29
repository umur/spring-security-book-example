package com.example.security.reactive;

import com.example.security.reactive.model.Item;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@Testcontainers
class ReactiveSecurityIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17-alpine");

    @DynamicPropertySource
    static void configureDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + postgres.getHost() + ":" + postgres.getMappedPort(5432)
                        + "/" + postgres.getDatabaseName());
        registry.add("spring.r2dbc.username", postgres::getUsername);
        registry.add("spring.r2dbc.password", postgres::getPassword);
        registry.add("spring.sql.init.schema-locations", () -> "classpath:schema-postgresql.sql");
        registry.add("spring.sql.init.mode", () -> "always");
    }

    @Autowired
    private WebTestClient webTestClient;

    @Nested
    @DisplayName("Full reactive flow with PostgreSQL")
    class FullFlow {

        @Test
        @DisplayName("unauthenticated request returns 401")
        void unauthenticatedReturns401() {
            webTestClient.get().uri("/api/items")
                    .exchange()
                    .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("USER cannot POST — returns 403")
        void userCannotPost() {
            webTestClient.post().uri("/api/items")
                    .headers(h -> h.setBasicAuth("user", "user"))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("""
                            {"name":"Forbidden","description":"should fail"}
                            """)
                    .exchange()
                    .expectStatus().isForbidden();
        }

        @Test
        @DisplayName("ADMIN creates item, then USER can retrieve it")
        void adminCreatesItemUserRetrievesIt() {
            // ADMIN creates
            Item created = webTestClient.post().uri("/api/items")
                    .headers(h -> h.setBasicAuth("admin", "admin"))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("""
                            {"name":"PostgresItem","description":"stored in postgres"}
                            """)
                    .exchange()
                    .expectStatus().isCreated()
                    .expectBody(Item.class)
                    .returnResult()
                    .getResponseBody();

            assertThat(created).isNotNull();
            assertThat(created.getId()).isNotNull();

            // USER retrieves it
            webTestClient.get().uri("/api/items/" + created.getId())
                    .headers(h -> h.setBasicAuth("user", "user"))
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(Item.class)
                    .value(item -> assertThat(item.getName()).isEqualTo("PostgresItem"));
        }

        @Test
        @DisplayName("USER can list all items")
        void userCanListItems() {
            // Create via admin first
            webTestClient.post().uri("/api/items")
                    .headers(h -> h.setBasicAuth("admin", "admin"))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("""
                            {"name":"ListItem","description":"for list test"}
                            """)
                    .exchange()
                    .expectStatus().isCreated();

            // List via user
            webTestClient.get().uri("/api/items")
                    .headers(h -> h.setBasicAuth("user", "user"))
                    .exchange()
                    .expectStatus().isOk()
                    .expectBodyList(Item.class)
                    .value(items -> assertThat(items).isNotEmpty());
        }
    }
}
