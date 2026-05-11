package com.cinetrack.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.List;

/**
 * Chapter 14: Token customizer — adds CineTrack-specific claims to every JWT.
 *
 * Three claims added to access tokens:
 *
 *   tier            — subscription tier; hardcoded to PREMIUM here, would come
 *                     from a UserDetailsService or database lookup in production.
 *   roles           — list of Spring Security role names stripped of the ROLE_ prefix.
 *   cinetrack_user_id — opaque identifier used by downstream services to avoid
 *                       leaking the internal database primary key.
 *
 * ID tokens are intentionally left unmodified: the tier and internal ID are not
 * part of the OIDC identity layer — they belong in the access token that services
 * use, not in the identity assertion that clients use.
 */
@Configuration
public class TokenCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            // Skip ID tokens — only enrich access tokens
            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                return;
            }

            Authentication principal = context.getPrincipal();

            // Service tokens (client_credentials) have no user principal
            if (principal == null || principal.getAuthorities() == null) {
                return;
            }

            List<String> roles = principal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .filter(authority -> authority.startsWith("ROLE_"))
                    .map(authority -> authority.substring("ROLE_".length()))
                    .toList();

            // Only add user-specific claims when there's an actual user
            if (!roles.isEmpty()) {
                context.getClaims().claim("tier", "PREMIUM");
                context.getClaims().claim("roles", roles);
                context.getClaims().claim("cinetrack_user_id",
                        "usr_" + principal.getName().hashCode());
            }
        };
    }
}
