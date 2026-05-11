package com.cinetrack.user;

import com.cinetrack.security.CineTrackOidcUserService;
import com.cinetrack.security.SecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Slice tests for UserController using the oauth2Login() post-processor.
 *
 * oauth2Login() injects a pre-built OidcUser into the SecurityContext so the
 * real IdP redirect never happens. This keeps tests fast and deterministic.
 */
@WebMvcTest(UserController.class)
@Import({SecurityConfig.class, CineTrackOidcUserService.class})
@ActiveProfiles("test")
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void userProfile_withOidcLogin_returns200() throws Exception {
        mockMvc.perform(get("/api/users/profile")
                        .with(oidcLogin()
                                .oidcUser(buildOidcUser("alice@cinetrack.io", "Alice Chen"))
                        ))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Alice Chen"))
                .andExpect(jsonPath("$.email").value("alice@cinetrack.io"));
    }

    @Test
    void userProfile_unauthenticated_redirectsToLogin() throws Exception {
        // oauth2Login flow redirects unauthenticated requests — not 401.
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void meEndpoint_returnsUserDetails() throws Exception {
        OidcUser oidcUser = buildOidcUser("bob@cinetrack.io", "Bob Martinez");

        mockMvc.perform(get("/api/users/me")
                        .with(oidcLogin().oidcUser(oidcUser)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Bob Martinez"))
                .andExpect(jsonPath("$.email").value("bob@cinetrack.io"));
    }

    // Builds a minimal OidcUser with the given email and name claims.
    private OidcUser buildOidcUser(String email, String name) {
        Map<String, Object> claims = Map.of(
                "sub", "user-" + email.hashCode(),
                "email", email,
                "name", name,
                "iat", Instant.now(),
                "exp", Instant.now().plusSeconds(3600)
        );
        OidcIdToken idToken = new OidcIdToken("id-token-value", Instant.now(),
                Instant.now().plusSeconds(3600), claims);
        return new DefaultOidcUser(List.of(), idToken);
    }
}
