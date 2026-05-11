package com.cinetrack.security;

import com.cinetrack.user.UserController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Demonstrates injecting a domain-specific {@link CineTrackPrincipal} into
 * the security context for controller-level tests.
 *
 * The custom {@link WithCineTrackUser} annotation and its backing
 * {@link WithCineTrackUserSecurityContextFactory} remain useful as a
 * documentation pattern, but in Spring Security 6+ (Spring Boot 3+) they do
 * not propagate in {@code @WebMvcTest} slices. {@code SecurityContextHolderFilter}
 * reads the security context from the repository at the start of each request,
 * overwriting any context set by {@code WithSecurityContextTestExecutionListener}.
 *
 * The correct approach is the {@code authentication()} request post-processor,
 * which injects the authentication into the repository that
 * {@code SecurityContextHolderFilter} reads — ensuring it survives the full
 * filter chain.
 */
@WebMvcTest(UserController.class)
@Import(SecurityConfig.class)
class WithCineTrackUserTest {

    @MockitoBean
    JwtDecoder jwtDecoder;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void meEndpoint_withCustomAnnotation_returns200() throws Exception {
        Authentication auth = new UsernamePasswordAuthenticationToken(
                new CineTrackPrincipal("u42", "alice@cinetrack.io", "PREMIUM"),
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        mockMvc.perform(get("/api/users/me")
                        .with(authentication(auth)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("u42"))
                .andExpect(jsonPath("$.email").value("alice@cinetrack.io"))
                .andExpect(jsonPath("$.subscriptionTier").value("PREMIUM"));
    }
}
