package com.example.security.oauth2login;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Login;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class OAuth2LoginSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Nested
    @DisplayName("Unauthenticated access")
    class UnauthenticatedAccess {

        @Test
        @DisplayName("unauthenticated request to dashboard redirects to login")
        void dashboardRedirectsToLogin() throws Exception {
            mockMvc.perform(get("/dashboard"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login"));
        }

        @Test
        @DisplayName("unauthenticated request to root redirects")
        void rootRedirects() throws Exception {
            mockMvc.perform(get("/"))
                    .andExpect(status().is3xxRedirection());
        }

        @Test
        @DisplayName("login page is publicly accessible")
        void loginPageIsPublic() throws Exception {
            mockMvc.perform(get("/login"))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("login page contains OAuth2 provider link")
        void loginPageShowsProviderLinks() throws Exception {
            mockMvc.perform(get("/login"))
                    .andExpect(status().isOk())
                    .andExpect(content().string(containsString("oauth2/authorization")));
        }
    }

    @Nested
    @DisplayName("OAuth2 authorization redirect")
    class AuthorizationRedirect {

        @Test
        @DisplayName("initiating OAuth2 login redirects to authorization endpoint")
        void oauth2LoginInitiatesRedirect() throws Exception {
            mockMvc.perform(get("/oauth2/authorization/mock-provider"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(header().string("Location",
                            containsString("oauth2/authorize")));
        }
    }

    @Nested
    @DisplayName("Authenticated access")
    class AuthenticatedAccess {

        @Test
        @DisplayName("user authenticated via oauth2Login() can access dashboard")
        void authenticatedUserAccessesDashboard() throws Exception {
            mockMvc.perform(get("/dashboard")
                            .with(oauth2Login()
                                    .attributes(attrs -> {
                                        attrs.put("sub", "user-123");
                                        attrs.put("name", "Alice OAuth");
                                        attrs.put("email", "alice@example.com");
                                    })
                            ))
                    .andExpect(status().isOk())
                    .andExpect(view().name("dashboard"));
        }

        @Test
        @DisplayName("OIDC user authenticated via oauth2Login() with OIDC claims can access dashboard")
        void oidcUserAccessesDashboard() throws Exception {
            mockMvc.perform(get("/dashboard")
                            .with(oauth2Login()
                                    .attributes(attrs -> {
                                        attrs.put("sub", "user-456");
                                        attrs.put("name", "Bob OIDC");
                                        attrs.put("email", "bob@example.com");
                                    })
                            ))
                    .andExpect(status().isOk())
                    .andExpect(view().name("dashboard"));
        }

        @Test
        @DisplayName("authenticated user redirected from root to dashboard")
        void rootRedirectsToDashboard() throws Exception {
            mockMvc.perform(get("/")
                            .with(oauth2Login().attributes(attrs -> attrs.put("sub", "u1"))))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/dashboard"));
        }
    }
}
