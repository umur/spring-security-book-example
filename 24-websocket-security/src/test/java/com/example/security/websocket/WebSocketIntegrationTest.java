package com.example.security.websocket;

import com.example.security.websocket.service.ChatService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.messaging.converter.JacksonJsonMessageConverter;
import org.springframework.messaging.simp.stomp.StompFrameHandler;
import org.springframework.messaging.simp.stomp.StompHeaders;
import org.springframework.messaging.simp.stomp.StompSession;
import org.springframework.messaging.simp.stomp.StompSessionHandlerAdapter;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.socket.WebSocketHttpHeaders;
import org.springframework.web.socket.client.standard.StandardWebSocketClient;
import org.springframework.web.socket.messaging.WebSocketStompClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.lang.reflect.Type;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
class WebSocketIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17-alpine");

    @DynamicPropertySource
    static void configureDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
        registry.add("spring.jpa.database-platform", () -> "org.hibernate.dialect.PostgreSQLDialect");
    }

    @Value("${local.server.port}")
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private ChatService chatService;

    private String wsUrl() {
        return "ws://localhost:" + port + "/ws";
    }

    private WebSocketStompClient buildStompClient() {
        WebSocketStompClient stompClient = new WebSocketStompClient(new StandardWebSocketClient());
        stompClient.setMessageConverter(new JacksonJsonMessageConverter());
        return stompClient;
    }

    @Nested
    @DisplayName("REST chat history endpoint")
    class ChatHistoryRest {

        @Test
        @DisplayName("unauthenticated access to /api/chat/history returns 401")
        void unauthenticatedReturns401() {
            var response = restTemplate.getForEntity("/api/chat/history", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("authenticated user can retrieve chat history")
        void authenticatedUserCanGetHistory() {
            var response = restTemplate.withBasicAuth("user", "user")
                    .getForEntity("/api/chat/history", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        @Test
        @DisplayName("chat history contains saved messages")
        void chatHistoryContainsSavedMessages() {
            chatService.saveMessage("testuser", "Hello, world!", "/topic/public");

            var response = restTemplate.withBasicAuth("user", "user")
                    .getForEntity("/api/chat/history", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("Hello, world!");
        }
    }

    @Nested
    @DisplayName("WebSocket STOMP connections")
    class StompConnections {

        @Test
        @DisplayName("authenticated user can connect via STOMP")
        void authenticatedUserCanConnect() throws Exception {
            WebSocketStompClient stompClient = buildStompClient();
            WebSocketHttpHeaders handshakeHeaders = new WebSocketHttpHeaders();
            String credentials = Base64.getEncoder().encodeToString("user:user".getBytes());
            handshakeHeaders.add("Authorization", "Basic " + credentials);

            StompSession session = stompClient.connectAsync(
                    wsUrl(), handshakeHeaders, new StompSessionHandlerAdapter() {}).get(5, TimeUnit.SECONDS);

            assertThat(session.isConnected()).isTrue();
            session.disconnect();
        }

        @Test
        @DisplayName("unauthenticated connection is rejected")
        void unauthenticatedConnectionIsRejected() throws Exception {
            WebSocketStompClient stompClient = buildStompClient();

            boolean rejected = false;
            try {
                StompSession session = stompClient.connectAsync(
                        wsUrl(), new StompSessionHandlerAdapter() {}).get(5, TimeUnit.SECONDS);
                // If connected, disconnect and mark as not rejected
                session.disconnect();
            } catch (Exception e) {
                rejected = true;
            }
            // With @EnableWebSocketSecurity requiring authentication on CONNECT,
            // unauthenticated connections should fail
            assertThat(rejected).isTrue();
        }

        @Test
        @DisplayName("authenticated user can subscribe to public topic and receive messages")
        void authenticatedUserCanSubscribeAndReceive() throws Exception {
            WebSocketStompClient stompClient = buildStompClient();
            WebSocketHttpHeaders handshakeHeaders = new WebSocketHttpHeaders();
            String credentials = Base64.getEncoder().encodeToString("user:user".getBytes());
            handshakeHeaders.add("Authorization", "Basic " + credentials);

            BlockingQueue<Map> received = new ArrayBlockingQueue<>(1);

            StompSession session = stompClient.connectAsync(
                    wsUrl(), handshakeHeaders, new StompSessionHandlerAdapter() {}).get(5, TimeUnit.SECONDS);

            session.subscribe("/topic/public", new StompFrameHandler() {
                @Override
                public Type getPayloadType(StompHeaders headers) {
                    return Map.class;
                }

                @Override
                public void handleFrame(StompHeaders headers, Object payload) {
                    received.offer((Map) payload);
                }
            });

            session.send("/app/chat.send", Map.of("content", "integration test message"));

            Map message = received.poll(5, TimeUnit.SECONDS);
            assertThat(message).isNotNull();
            assertThat(message.get("content")).isEqualTo("integration test message");
            assertThat(message.get("sender")).isEqualTo("user");

            session.disconnect();
        }
    }
}
