package com.example.security.reactive;

import com.example.security.reactive.model.Item;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class ReactiveSecurityTest {

    @Autowired
    private WebTestClient webTestClient;

    @Nested
    @DisplayName("GET /api/items — list items")
    class ListItems {

        @Test
        @DisplayName("unauthenticated request returns 401")
        void unauthenticatedReturns401() {
            webTestClient.get().uri("/api/items")
                    .exchange()
                    .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("authenticated USER can list items")
        void authenticatedUserCanListItems() {
            webTestClient.get().uri("/api/items")
                    .headers(h -> h.setBasicAuth("user", "user"))
                    .exchange()
                    .expectStatus().isOk();
        }

        @Test
        @DisplayName("authenticated ADMIN can list items")
        void authenticatedAdminCanListItems() {
            webTestClient.get().uri("/api/items")
                    .headers(h -> h.setBasicAuth("admin", "admin"))
                    .exchange()
                    .expectStatus().isOk();
        }
    }

    @Nested
    @DisplayName("POST /api/items — create item")
    class CreateItem {

        @Test
        @DisplayName("unauthenticated request returns 401")
        void unauthenticatedReturns401() {
            webTestClient.post().uri("/api/items")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("""
                            {"name":"Test","description":"desc"}
                            """)
                    .exchange()
                    .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("USER role cannot create item — returns 403")
        void userCannotCreateItem() {
            webTestClient.post().uri("/api/items")
                    .headers(h -> h.setBasicAuth("user", "user"))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("""
                            {"name":"Test","description":"desc"}
                            """)
                    .exchange()
                    .expectStatus().isForbidden();
        }

        @Test
        @DisplayName("ADMIN can create item — returns 201")
        void adminCanCreateItem() {
            webTestClient.post().uri("/api/items")
                    .headers(h -> h.setBasicAuth("admin", "admin"))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("""
                            {"name":"AdminItem","description":"Created by admin"}
                            """)
                    .exchange()
                    .expectStatus().isCreated()
                    .expectBody(Item.class)
                    .value(item -> assertThat(item.getName()).isEqualTo("AdminItem"));
        }
    }

    @Nested
    @DisplayName("GET /api/items/{id} — get single item")
    class GetItem {

        @Test
        @DisplayName("unauthenticated request returns 401")
        void unauthenticatedReturns401() {
            webTestClient.get().uri("/api/items/1")
                    .exchange()
                    .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("authenticated user gets 404 for non-existent item")
        void authenticatedUserGets404ForMissingItem() {
            webTestClient.get().uri("/api/items/999999")
                    .headers(h -> h.setBasicAuth("user", "user"))
                    .exchange()
                    .expectStatus().isNotFound();
        }
    }
}
