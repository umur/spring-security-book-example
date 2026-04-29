package com.example.security.websocket.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.socket.EnableWebSocketSecurity;
import org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager;

/**
 * Configures WebSocket/STOMP message-level security.
 *
 * Uses @EnableWebSocketSecurity which installs:
 *  - SecurityContextChannelInterceptor — propagates the authenticated principal into the STOMP channel
 *  - AuthorizationChannelInterceptor  — enforces the authorization rules below
 *  - XorCsrfChannelInterceptor        — CSRF for STOMP (overridden to no-op below for Basic-auth scenarios)
 *
 * Authorization rules:
 *  - CONNECT:              any authenticated user
 *  - subscribe /topic/public:  any authenticated user
 *  - subscribe /topic/admin:   ADMIN role only
 *  - send to /app/chat.send:   any authenticated user
 *  - everything else:      authenticated
 */
@Configuration
@EnableWebSocketSecurity
public class WebSocketSecurityConfig {

    /**
     * Override the CSRF channel interceptor with a no-op so that HTTP-Basic-authenticated
     * WebSocket connections are not rejected for missing CSRF tokens.
     * The bean name "csrfChannelInterceptor" is looked up by
     * WebSocketMessageBrokerSecurityConfiguration and replaces the default
     * XorCsrfChannelInterceptor when present.
     */
    @Bean("csrfChannelInterceptor")
    ChannelInterceptor noOpCsrfChannelInterceptor() {
        return new ChannelInterceptor() {};
    }

    @Bean
    AuthorizationManager<Message<?>> messageAuthorizationManager(
            MessageMatcherDelegatingAuthorizationManager.Builder messages) {
        messages
                .simpTypeMatchers(SimpMessageType.CONNECT).authenticated()
                .simpSubscribeDestMatchers("/topic/public").authenticated()
                .simpSubscribeDestMatchers("/topic/admin").hasRole("ADMIN")
                .simpDestMatchers("/app/chat.send").authenticated()
                .anyMessage().authenticated();
        return messages.build();
    }
}
