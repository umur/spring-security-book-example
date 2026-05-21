package com.cinetrack.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for SocialUserService.loadUser() enrichment logic.
 *
 * DefaultOAuth2UserService.loadUser() calls the UserInfo endpoint over HTTP,
 * so we replace the private delegate via ReflectionTestUtils with a stub that
 * returns a pre-built OAuth2User. This lets us test only the enrichment logic
 * (subscription_tier, cinetrack_user_id) in isolation without any network call.
 */
class SocialUserServiceUnitTest {

    @Test
    void loadUser_enrichesAttributesWithSubscriptionTierAndCinetrackUserId() {
        SocialUserService service = new SocialUserService();

        // Replace the private delegate with a stub that returns a known user
        DefaultOAuth2UserService stubDelegate = new DefaultOAuth2UserService() {
            @Override
            public OAuth2User loadUser(OAuth2UserRequest userRequest) {
                return new DefaultOAuth2User(
                        List.of(new SimpleGrantedAuthority("ROLE_USER")),
                        Map.of(
                                "sub", "google-sub-123",
                                "email", "alice@example.com",
                                "name", "Alice"
                        ),
                        "email"
                );
            }
        };
        ReflectionTestUtils.setField(service, "delegate", stubDelegate);

        ClientRegistration registration = ClientRegistration.withRegistrationId("google")
                .clientId("test-client-id")
                .clientSecret("test-secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost/callback")
                .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                .tokenUri("https://oauth2.googleapis.com/token")
                .userInfoUri("https://openidconnect.googleapis.com/v1/userinfo")
                .userNameAttributeName("email")
                .scope("openid", "profile", "email")
                .build();

        OAuth2AccessToken token = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "test-token",
                Instant.now(),
                Instant.now().plusSeconds(3600),
                Set.of("openid", "profile", "email")
        );

        OAuth2UserRequest request = new OAuth2UserRequest(registration, token);
        OAuth2User result = service.loadUser(request);

        assertThat(result).isNotNull();
        assertThat((String) result.getAttribute("subscription_tier")).isEqualTo("PREMIUM");
        assertThat((String) result.getAttribute("cinetrack_user_id")).startsWith("usr_");
        assertThat((String) result.getAttribute("email")).isEqualTo("alice@example.com");
        assertThat(result.getAuthorities())
                .extracting("authority")
                .containsExactly("ROLE_USER");
        // Principal name is the "email" attribute
        assertThat(result.getName()).isEqualTo("alice@example.com");
    }

    @Test
    void loadUser_cinetrackUserId_derivedFromEmailHash() {
        SocialUserService service = new SocialUserService();

        DefaultOAuth2UserService stubDelegate = new DefaultOAuth2UserService() {
            @Override
            public OAuth2User loadUser(OAuth2UserRequest userRequest) {
                return new DefaultOAuth2User(
                        List.of(new SimpleGrantedAuthority("ROLE_USER")),
                        Map.of("email", "bob@cinetrack.io", "name", "Bob"),
                        "email"
                );
            }
        };
        ReflectionTestUtils.setField(service, "delegate", stubDelegate);

        ClientRegistration registration = ClientRegistration.withRegistrationId("google")
                .clientId("test-client-id")
                .clientSecret("test-secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost/callback")
                .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                .tokenUri("https://oauth2.googleapis.com/token")
                .userInfoUri("https://openidconnect.googleapis.com/v1/userinfo")
                .userNameAttributeName("email")
                .scope("openid")
                .build();

        OAuth2AccessToken token = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, "tok",
                Instant.now(), Instant.now().plusSeconds(3600));

        OAuth2User result = service.loadUser(new OAuth2UserRequest(registration, token));

        String expectedId = "usr_" + "bob@cinetrack.io".hashCode();
        assertThat((String) result.getAttribute("cinetrack_user_id")).isEqualTo(expectedId);
    }
}
