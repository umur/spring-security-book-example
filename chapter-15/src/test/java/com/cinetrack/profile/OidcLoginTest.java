package com.cinetrack.profile;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import com.cinetrack.security.CineTrackOidcUserService;
import com.cinetrack.security.SecurityConfig;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Chapter 15: Slice tests for the OIDC login flow.
 *
 * SecurityMockMvcRequestPostProcessors.oidcLogin() bypasses the real IdP redirect
 * and injects a pre-built OidcUser into the SecurityContext. This lets us test
 * authorization rules and principal mapping without starting a browser or a server.
 */
@WebMvcTest(ProfileController.class)
@Import({SecurityConfig.class, CineTrackOidcUserService.class})
class OidcLoginTest {

    @Autowired
    private MockMvc mockMvc;

    /**
     * An OIDC-authenticated user must see their profile data at /api/me.
     * The email claim from the ID token must appear in the response body.
     */
    @Test
    void getMe_withOidcLogin_returns200WithEmail() throws Exception {
        mockMvc.perform(get("/api/me")
                        .with(oidcLogin()
                                .idToken(token -> token
                                        .claim("email", "alice@gmail.com")
                                        .claim("name", "Alice")
                                        .subject("alice@gmail.com")
                                )
                        )
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("alice@gmail.com"));
    }

    /**
     * Unauthenticated requests to /api/me must be redirected to the login page,
     * not rejected with 401. The oauth2Login() mechanism uses redirects.
     */
    @Test
    void getMe_withoutAuth_redirectsToLogin() throws Exception {
        mockMvc.perform(get("/api/me"))
                .andExpect(status().is3xxRedirection());
    }
}
