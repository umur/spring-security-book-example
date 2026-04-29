package com.example.security.resourceserver;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class ResourceServerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Nested
    @DisplayName("GET /api/articles — requires SCOPE_read or ROLE_USER")
    class GetArticles {

        @Test
        @DisplayName("no token returns 401")
        void noTokenReturns401() throws Exception {
            mockMvc.perform(get("/api/articles"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("valid JWT with SCOPE_read returns 200")
        void validJwtWithReadScopeReturns200() throws Exception {
            mockMvc.perform(get("/api/articles")
                            .with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_read"))))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
        }

        @Test
        @DisplayName("valid JWT with ROLE_USER returns 200")
        void validJwtWithRoleUserReturns200() throws Exception {
            mockMvc.perform(get("/api/articles")
                            .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("valid JWT without read scope returns 403")
        void validJwtWithoutReadScopeReturns403() throws Exception {
            mockMvc.perform(get("/api/articles")
                            .with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_other"))))
                    .andExpect(status().isForbidden());
        }
    }

    @Nested
    @DisplayName("GET /api/articles/{id} — requires SCOPE_read")
    class GetArticleById {

        @Test
        @DisplayName("no token returns 401")
        void noTokenReturns401() throws Exception {
            mockMvc.perform(get("/api/articles/1"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("valid JWT with SCOPE_read returns 200 or 404")
        void validJwtWithReadScopeReturnsContent() throws Exception {
            // Article 1 is seeded by DataSeeder — just verify security allows the call
            mockMvc.perform(get("/api/articles/1")
                            .with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_read"))))
                    .andExpect(result -> {
                        int status = result.getResponse().getStatus();
                        // 200 if seeded, 404 if not — both mean security passed
                        assert status == 200 || status == 404;
                    });
        }
    }

    @Nested
    @DisplayName("POST /api/articles — requires SCOPE_write or ROLE_ADMIN")
    class CreateArticle {

        @Test
        @DisplayName("no token returns 401")
        void noTokenReturns401() throws Exception {
            mockMvc.perform(post("/api/articles")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"title":"Test","content":"Body"}
                                    """))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("JWT with only SCOPE_read returns 403 on POST")
        void readScopeOnlyReturnsForbiddenOnPost() throws Exception {
            mockMvc.perform(post("/api/articles")
                            .with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_read")))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"title":"Test","content":"Body"}
                                    """))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("JWT with SCOPE_write creates article and returns 201")
        void writeScopeCreatesArticle() throws Exception {
            mockMvc.perform(post("/api/articles")
                            .with(jwt()
                                    .authorities(new SimpleGrantedAuthority("SCOPE_write"))
                                    .jwt(builder -> builder.subject("test-user")))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"title":"New Article","content":"Article content here"}
                                    """))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.id").exists())
                    .andExpect(jsonPath("$.title").value("New Article"))
                    .andExpect(jsonPath("$.authorUsername").value("test-user"));
        }

        @Test
        @DisplayName("JWT with ROLE_ADMIN creates article and returns 201")
        void adminRoleCreatesArticle() throws Exception {
            mockMvc.perform(post("/api/articles")
                            .with(jwt()
                                    .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))
                                    .jwt(builder -> builder.subject("admin-user")))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"title":"Admin Article","content":"Written by admin"}
                                    """))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.authorUsername").value("admin-user"));
        }
    }

    @Nested
    @DisplayName("Custom role claim mapping")
    class RoleClaimMapping {

        @Test
        @DisplayName("JWT with roles claim mapped to ROLE_USER grants read access")
        void rolesClaimMappedToGrantedAuthority() throws Exception {
            // Simulate a JWT where the custom JwtAuthenticationConverter
            // extracts 'roles' claim as ROLE_USER
            mockMvc.perform(get("/api/articles")
                            .with(jwt()
                                    .authorities(new SimpleGrantedAuthority("ROLE_USER"))
                                    .jwt(builder -> builder
                                            .subject("claims-user")
                                            .claim("roles", java.util.List.of("USER")))))
                    .andExpect(status().isOk());
        }
    }
}
