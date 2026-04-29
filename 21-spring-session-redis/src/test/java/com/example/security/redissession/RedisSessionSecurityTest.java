package com.example.security.redissession;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class RedisSessionSecurityTest {

    @Container
    @SuppressWarnings("resource")
    static GenericContainer<?> redis =
            new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);

    @DynamicPropertySource
    static void configureRedis(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
    }

    @Autowired
    private MockMvc mockMvc;

    @Nested
    @DisplayName("Unauthenticated access")
    class UnauthenticatedAccess {

        @Test
        @DisplayName("unauthenticated request to dashboard redirects to login")
        void unauthenticatedDashboardRedirectsToLogin() throws Exception {
            mockMvc.perform(get("/dashboard"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login"));
        }

        @Test
        @DisplayName("unauthenticated request to session info redirects to login")
        void unauthenticatedSessionInfoRedirectsToLogin() throws Exception {
            mockMvc.perform(get("/api/session/info"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login"));
        }

        @Test
        @DisplayName("login page is publicly accessible")
        void loginPageIsPublic() throws Exception {
            mockMvc.perform(get("/login"))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("Authenticated access")
    class AuthenticatedAccess {

        @Test
        @DisplayName("authenticated user can access dashboard")
        void authenticatedUserAccessesDashboard() throws Exception {
            mockMvc.perform(get("/dashboard").with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(view().name("dashboard"));
        }

        @Test
        @DisplayName("session info endpoint returns session details as JSON")
        void sessionInfoReturnsJson() throws Exception {
            mockMvc.perform(get("/api/session/info").with(user("user").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith("application/json"))
                    .andExpect(jsonPath("$.username").value("user"))
                    .andExpect(jsonPath("$.sessionId").isNotEmpty())
                    .andExpect(jsonPath("$.creationTime").isNotEmpty())
                    .andExpect(jsonPath("$.maxInactiveInterval").isNumber());
        }

        @Test
        @DisplayName("setting session attribute persists it within the same session")
        void settingSessionAttributePersists() throws Exception {
            mockMvc.perform(post("/api/session/attribute")
                            .with(user("user").roles("USER"))
                            .with(csrf())
                            .contentType("application/json")
                            .content("{\"name\":\"color\",\"value\":\"blue\"}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.name").value("color"))
                    .andExpect(jsonPath("$.value").value("blue"))
                    .andExpect(jsonPath("$.sessionId").isNotEmpty());
        }
    }
}
