package com.example.security.websocket;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class WebSocketSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Nested
    @DisplayName("Chat history REST endpoint")
    class ChatHistoryEndpoint {

        @Test
        @DisplayName("unauthenticated request to /api/chat/history returns 401")
        void unauthenticatedReturns401() throws Exception {
            mockMvc.perform(get("/api/chat/history"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("authenticated USER can access /api/chat/history")
        void authenticatedUserCanAccessHistory() throws Exception {
            mockMvc.perform(get("/api/chat/history")
                            .with(user("user").roles("USER")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("authenticated ADMIN can access /api/chat/history")
        void authenticatedAdminCanAccessHistory() throws Exception {
            mockMvc.perform(get("/api/chat/history")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk());
        }
    }
}
