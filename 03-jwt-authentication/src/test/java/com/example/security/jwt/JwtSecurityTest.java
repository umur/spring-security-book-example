package com.example.security.jwt;

import com.example.security.jwt.config.JwtProperties;
import com.example.security.jwt.service.JwtService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class JwtSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private JwtProperties jwtProperties;

    private String validTokenForUser() {
        var userDetails = new User("user", "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
        return jwtService.generateAccessToken(userDetails);
    }

    @Nested
    @DisplayName("POST /api/auth/login")
    class Login {

        @Test
        @DisplayName("Valid credentials return 200 with JWT token")
        void validCredentialsReturn200WithToken() throws Exception {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"username":"user","password":"user"}
                                    """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").isNotEmpty())
                    .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                    .andExpect(jsonPath("$.tokenType").value("Bearer"));
        }

        @Test
        @DisplayName("Invalid credentials return 401")
        void invalidCredentialsReturn401() throws Exception {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"username":"user","password":"wrongpassword"}
                                    """))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Admin with valid credentials gets 200")
        void adminValidCredentialsReturn200() throws Exception {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"username":"admin","password":"admin"}
                                    """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").isNotEmpty());
        }
    }

    @Nested
    @DisplayName("GET /api/tasks")
    class GetTasks {

        @Test
        @DisplayName("Request without token returns 401")
        void withoutTokenReturns401() throws Exception {
            mockMvc.perform(get("/api/tasks"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Request with valid Bearer token returns 200")
        void withValidTokenReturns200() throws Exception {
            String token = validTokenForUser();
            mockMvc.perform(get("/api/tasks")
                            .header("Authorization", "Bearer " + token))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
        }

        @Test
        @DisplayName("Request with expired token returns 401")
        void withExpiredTokenReturns401() throws Exception {
            JwtProperties shortLived = new JwtProperties(
                    jwtProperties.secret(), -1000L, jwtProperties.refreshExpiration());
            JwtService shortLivedService = new JwtService(shortLived);
            var ud = new User("user", "password",
                    List.of(new SimpleGrantedAuthority("ROLE_USER")));
            String expiredToken = shortLivedService.generateAccessToken(ud);

            mockMvc.perform(get("/api/tasks")
                            .header("Authorization", "Bearer " + expiredToken))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Request with malformed token returns 401")
        void withMalformedTokenReturns401() throws Exception {
            mockMvc.perform(get("/api/tasks")
                            .header("Authorization", "Bearer this.is.not.valid"))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("POST /api/tasks")
    class CreateTask {

        @Test
        @DisplayName("With valid token creates task and returns 201")
        void withValidTokenCreatesTask() throws Exception {
            String token = validTokenForUser();
            mockMvc.perform(post("/api/tasks")
                            .header("Authorization", "Bearer " + token)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"title":"My Task","description":"Task description"}
                                    """))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.id").exists())
                    .andExpect(jsonPath("$.title").value("My Task"))
                    .andExpect(jsonPath("$.ownerUsername").value("user"));
        }
    }
}
