package com.cinetrack.profile;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import com.cinetrack.security.CineTrackOidcUserService;
import com.cinetrack.security.SecurityConfig;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Login;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Chapter 15: Slice tests using the oauth2Login() post-processor.
 *
 * oauth2Login() injects a DefaultOAuth2User (no ID token) — useful when
 * testing the OAuth2 login path without the OIDC layer.
 */
@WebMvcTest(ProfileController.class)
@Import({SecurityConfig.class, CineTrackOidcUserService.class})
class OAuth2LoginTest {

    @Autowired
    private MockMvc mockMvc;

    /**
     * A user authenticated via the OAuth2 (non-OIDC) path must still be able
     * to reach /api/me — the endpoint is secured by authentication, not by
     * the specific login mechanism.
     */
    @Test
    void getMe_withOAuth2Login_returns200() throws Exception {
        mockMvc.perform(get("/api/me")
                        .with(oauth2Login()
                                .attributes(attrs -> {
                                    attrs.put("email", "alice@gmail.com");
                                    attrs.put("name", "Alice");
                                    attrs.put("subscription_tier", "PREMIUM");
                                })
                        )
                )
                .andExpect(status().isOk());
    }
}
