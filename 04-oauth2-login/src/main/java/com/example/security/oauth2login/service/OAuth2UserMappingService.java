package com.example.security.oauth2login.service;

import com.example.security.oauth2login.model.OAuthUser;
import com.example.security.oauth2login.repository.OAuthUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

/**
 * Maps OAuth2 / OIDC provider attributes to a locally persisted {@link OAuthUser},
 * creating or updating the record on every successful login.
 */
@Service
@RequiredArgsConstructor
public class OAuth2UserMappingService {

    private final OAuthUserRepository oAuthUserRepository;
    private final OidcUserService delegateOidc = new OidcUserService();
    private final DefaultOAuth2UserService delegateOAuth2 = new DefaultOAuth2UserService();

    // -----------------------------------------------------------------------
    // OIDC flow (e.g. Google)
    // -----------------------------------------------------------------------

    @Transactional
    public OidcUser loadOidcUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = delegateOidc.loadUser(userRequest);

        String provider   = userRequest.getClientRegistration().getRegistrationId();
        String providerId = oidcUser.getSubject();
        String email      = oidcUser.getEmail();
        String name       = oidcUser.getFullName() != null ? oidcUser.getFullName() : email;
        String avatar     = oidcUser.getPicture();

        OAuthUser local = findOrCreate(provider, providerId, email, name, avatar);

        var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + local.getRole()));
        return new DefaultOidcUser(authorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
    }

    // -----------------------------------------------------------------------
    // Generic OAuth2 flow (e.g. GitHub)
    // -----------------------------------------------------------------------

    @Transactional
    public OAuth2User loadOAuth2User(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = delegateOAuth2.loadUser(userRequest);

        String provider   = userRequest.getClientRegistration().getRegistrationId();
        String providerId = oauth2User.getAttribute("id") != null
                ? String.valueOf(oauth2User.<Object>getAttribute("id"))
                : oauth2User.getName();
        String email      = resolveEmail(oauth2User);
        String name       = oauth2User.getAttribute("name") != null
                ? oauth2User.getAttribute("name")
                : email;
        String avatar     = oauth2User.getAttribute("avatar_url");

        OAuthUser local = findOrCreate(provider, providerId, email, name, avatar);

        var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + local.getRole()));
        // Use "login" as the nameAttributeKey for GitHub; fall back to "sub"
        String nameAttributeKey = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
        return new DefaultOAuth2User(authorities, oauth2User.getAttributes(), nameAttributeKey);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    private OAuthUser findOrCreate(String provider, String providerId,
                                   String email, String name, String avatar) {
        return oAuthUserRepository.findByProviderAndProviderId(provider, providerId)
                .map(existing -> {
                    existing.setEmail(email);
                    existing.setName(name);
                    existing.setAvatarUrl(avatar);
                    return oAuthUserRepository.save(existing);
                })
                .orElseGet(() -> oAuthUserRepository.save(
                        new OAuthUser(provider, providerId, email, name, avatar)));
    }

    private String resolveEmail(OAuth2User user) {
        String email = user.getAttribute("email");
        return email != null ? email : user.getName() + "@oauth2.local";
    }

    public OAuthUser findByProviderAndProviderId(String provider, String providerId) {
        return oAuthUserRepository.findByProviderAndProviderId(provider, providerId).orElse(null);
    }
}
