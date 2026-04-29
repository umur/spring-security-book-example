package com.example.security.apikey;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ApiKeySecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Nested
    @DisplayName("No API key header")
    class NoApiKey {

        @Test
        @DisplayName("GET /api/data without X-API-Key header returns 401")
        void noApiKeyReturns401() throws Exception {
            mockMvc.perform(get("/api/data"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("GET /api/data/admin without X-API-Key header returns 401")
        void noApiKeyOnAdminReturns401() throws Exception {
            mockMvc.perform(get("/api/data/admin"))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("Invalid API key")
    class InvalidApiKey {

        @Test
        @DisplayName("GET /api/data with invalid X-API-Key returns 401")
        void invalidApiKeyReturns401() throws Exception {
            mockMvc.perform(get("/api/data")
                            .header("X-API-Key", "totally-invalid-key-value"))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("Valid API key with USER scope")
    class UserScopeApiKey {

        @Test
        @DisplayName("USER scope can access GET /api/data — returns 200")
        void userScopeCanAccessData() throws Exception {
            mockMvc.perform(get("/api/data")
                            .with(user("client").roles("USER")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("USER scope cannot access GET /api/data/admin — returns 403")
        void userScopeCannotAccessAdminData() throws Exception {
            mockMvc.perform(get("/api/data/admin")
                            .with(user("client").roles("USER")))
                    .andExpect(status().isForbidden());
        }
    }

    @Nested
    @DisplayName("Valid API key with ADMIN scope")
    class AdminScopeApiKey {

        @Test
        @DisplayName("ADMIN scope can access GET /api/data/admin — returns 200")
        void adminScopeCanAccessAdminData() throws Exception {
            mockMvc.perform(get("/api/data/admin")
                            .with(user("admin-client").roles("ADMIN")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("ADMIN scope can also access GET /api/data — returns 200")
        void adminScopeCanAccessData() throws Exception {
            mockMvc.perform(get("/api/data")
                            .with(user("admin-client").roles("ADMIN")))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("Admin key generation endpoint")
    class KeyGenerationEndpoint {

        @Test
        @DisplayName("POST /api/keys without HTTP Basic returns 401")
        void generateKeyWithoutBasicAuthReturns401() throws Exception {
            mockMvc.perform(post("/api/keys")
                            .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                            .content("""
                                    {"owner":"test-client","roles":"USER"}
                                    """))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("POST /api/keys with ADMIN HTTP Basic returns 201")
        void generateKeyWithAdminBasicAuthReturns201() throws Exception {
            mockMvc.perform(post("/api/keys")
                            .with(user("admin").roles("ADMIN"))
                            .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                            .content("""
                                    {"owner":"test-client","roles":"USER"}
                                    """))
                    .andExpect(status().isCreated());
        }

        @Test
        @DisplayName("POST /api/keys with non-ADMIN HTTP Basic returns 403")
        void generateKeyWithNonAdminReturns403() throws Exception {
            mockMvc.perform(post("/api/keys")
                            .with(user("someone").roles("USER"))
                            .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                            .content("""
                                    {"owner":"test-client","roles":"USER"}
                                    """))
                    .andExpect(status().isForbidden());
        }
    }
}
