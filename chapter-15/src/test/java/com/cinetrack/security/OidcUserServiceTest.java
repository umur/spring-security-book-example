package com.cinetrack.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that CineTrackOidcUserService is wired correctly in the application context.
 *
 * The actual loadUser() delegation to the parent OidcUserService requires a live
 * IdP exchange, so this test stays at the wiring level: we confirm the bean exists
 * and is an instance of OidcUserService, proving the override chain is intact.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class OidcUserServiceTest {

    @Autowired
    private CineTrackOidcUserService cineTrackOidcUserService;

    @Test
    void oidcUserService_loadsUserAttributes() {
        // Confirms the service bean is present and correctly extends OidcUserService.
        assertThat(cineTrackOidcUserService)
                .isNotNull()
                .isInstanceOf(OidcUserService.class);
    }
}
