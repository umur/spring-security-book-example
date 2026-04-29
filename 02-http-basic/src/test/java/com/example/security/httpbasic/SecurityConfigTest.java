package com.example.security.httpbasic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Nested
    @DisplayName("Unauthenticated access")
    class UnauthenticatedAccess {

        @Test
        @DisplayName("GET /api/notes without credentials returns 401")
        void unauthenticatedGetReturns401() throws Exception {
            mockMvc.perform(get("/api/notes"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("POST /api/notes without credentials returns 401")
        void unauthenticatedPostReturns401() throws Exception {
            mockMvc.perform(post("/api/notes")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"title":"Test","content":"Body"}
                                    """))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("401 response does not return HTML")
        void unauthorizedResponseIsNotHtml() throws Exception {
            mockMvc.perform(get("/api/notes"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(header().doesNotExist("Content-Type"));
        }
    }

    @Nested
    @DisplayName("Authenticated access")
    class AuthenticatedAccess {

        @Test
        @DisplayName("USER can GET /api/notes and receives JSON")
        void userCanGetNotes() throws Exception {
            mockMvc.perform(get("/api/notes")
                            .with(user("user").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
        }

        @Test
        @DisplayName("ADMIN can POST /api/notes")
        void adminCanCreateNote() throws Exception {
            mockMvc.perform(post("/api/notes")
                            .with(user("admin").roles("ADMIN"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"title":"Admin Note","content":"Admin content"}
                                    """))
                    .andExpect(status().isCreated())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
        }

        @Test
        @DisplayName("USER can also POST /api/notes")
        void userCanCreateNote() throws Exception {
            mockMvc.perform(post("/api/notes")
                            .with(user("user").roles("USER"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"title":"User Note","content":"User content"}
                                    """))
                    .andExpect(status().isCreated())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
        }

        @Test
        @DisplayName("Response is JSON, not HTML")
        void responseIsJson() throws Exception {
            mockMvc.perform(get("/api/notes")
                            .with(user("user").roles("USER"))
                            .accept(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
        }
    }
}
