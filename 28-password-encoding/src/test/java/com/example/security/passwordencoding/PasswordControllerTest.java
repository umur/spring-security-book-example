package com.example.security.passwordencoding;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.hamcrest.Matchers.startsWith;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("PasswordController Tests")
class PasswordControllerTest {

    @Autowired
    private MockMvc mockMvc;

    // Helper: extract a JSON field value from a response body string without ObjectMapper
    private String extractJsonField(String json, String field) {
        // Matches "field":"value" patterns
        String search = "\"" + field + "\":\"";
        int start = json.indexOf(search);
        if (start == -1) return "";
        start += search.length();
        int end = json.indexOf("\"", start);
        return json.substring(start, end);
    }

    @Nested
    @DisplayName("GET /api/passwords/encode")
    class EncodeEndpoint {

        @Test
        @DisplayName("returns 401 when unauthenticated")
        void unauthenticatedReturns401() throws Exception {
            mockMvc.perform(get("/api/passwords/encode").param("raw", "secret"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("encodes with default bcrypt algorithm")
        void encodesWithBcryptDefault() throws Exception {
            mockMvc.perform(get("/api/passwords/encode")
                            .param("raw", "secret")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.algorithm").value("bcrypt"))
                    .andExpect(jsonPath("$.raw").value("secret"))
                    .andExpect(jsonPath("$.encoded").isNotEmpty());
        }

        @Test
        @DisplayName("encodes with argon2 algorithm")
        void encodesWithArgon2() throws Exception {
            mockMvc.perform(get("/api/passwords/encode")
                            .param("raw", "secret")
                            .param("algorithm", "argon2")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.algorithm").value("argon2"))
                    .andExpect(jsonPath("$.encoded").isNotEmpty());
        }

        @Test
        @DisplayName("encodes with pbkdf2 algorithm")
        void encodesWithPbkdf2() throws Exception {
            mockMvc.perform(get("/api/passwords/encode")
                            .param("raw", "secret")
                            .param("algorithm", "pbkdf2")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.algorithm").value("pbkdf2"))
                    .andExpect(jsonPath("$.encoded").isNotEmpty());
        }

        @Test
        @DisplayName("encodes with delegating algorithm and result starts with {bcrypt}")
        void encodesWithDelegating() throws Exception {
            mockMvc.perform(get("/api/passwords/encode")
                            .param("raw", "secret")
                            .param("algorithm", "delegating")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.encoded", startsWith("{bcrypt}")));
        }
    }

    @Nested
    @DisplayName("POST /api/passwords/verify")
    class VerifyEndpoint {

        @Test
        @DisplayName("returns true when password matches delegating-encoded hash")
        void returnsTrueForMatchingPassword() throws Exception {
            // Step 1: encode via GET
            MvcResult encodeResult = mockMvc.perform(get("/api/passwords/encode")
                            .param("raw", "myPass")
                            .param("algorithm", "delegating")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andReturn();

            String encoded = extractJsonField(encodeResult.getResponse().getContentAsString(), "encoded");

            // Step 2: verify via POST — build JSON body as a string to avoid Jackson dependency
            String requestBody = "{\"raw\":\"myPass\",\"encoded\":\"" + encoded + "\",\"algorithm\":\"delegating\"}";

            mockMvc.perform(post("/api/passwords/verify")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestBody)
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.matches").value(true));
        }

        @Test
        @DisplayName("returns false when wrong password is submitted")
        void returnsFalseForWrongPassword() throws Exception {
            MvcResult encodeResult = mockMvc.perform(get("/api/passwords/encode")
                            .param("raw", "correctPass")
                            .param("algorithm", "delegating")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andReturn();

            String encoded = extractJsonField(encodeResult.getResponse().getContentAsString(), "encoded");

            String requestBody = "{\"raw\":\"wrongPass\",\"encoded\":\"" + encoded + "\",\"algorithm\":\"delegating\"}";

            mockMvc.perform(post("/api/passwords/verify")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestBody)
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.matches").value(false));
        }

        @Test
        @DisplayName("returns 401 when unauthenticated")
        void unauthenticatedReturns401() throws Exception {
            String body = "{\"raw\":\"pass\",\"encoded\":\"{bcrypt}$2a$12$abc\"}";
            mockMvc.perform(post("/api/passwords/verify")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(body))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("GET /api/passwords/info")
    class InfoEndpoint {

        @Test
        @DisplayName("returns info about DelegatingPasswordEncoder")
        void returnsInfo() throws Exception {
            mockMvc.perform(get("/api/passwords/info")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.currentDefault").value("bcrypt"))
                    .andExpect(jsonPath("$.description").isNotEmpty())
                    .andExpect(jsonPath("$.migrationSteps").isArray());
        }

        @Test
        @DisplayName("returns 401 when unauthenticated")
        void unauthenticatedReturns401() throws Exception {
            mockMvc.perform(get("/api/passwords/info"))
                    .andExpect(status().isUnauthorized());
        }
    }
}
