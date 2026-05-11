package com.cinetrack.security;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Chapter 15: Maps the raw Google OAuth2 attributes to a CineTrack principal.
 *
 * The DefaultOAuth2UserService fetches the UserInfo endpoint response.
 * This service then enriches it with CineTrack-specific attributes
 * (subscription_tier, internal user identifier) that downstream logic needs.
 *
 * In production, the enrichment would involve a database lookup by email;
 * here it is hardcoded to keep the example self-contained.
 */
@Service
public class SocialUserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User googleUser = delegate.loadUser(userRequest);

        // Build enriched attribute map
        Map<String, Object> attributes = new HashMap<>(googleUser.getAttributes());
        attributes.put("subscription_tier", "PREMIUM");
        attributes.put("cinetrack_user_id", "usr_" + attributes.get("email").hashCode());

        return new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                attributes,
                "email"   // the attribute that serves as the principal name
        );
    }
}
