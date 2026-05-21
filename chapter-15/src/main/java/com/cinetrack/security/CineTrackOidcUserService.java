package com.cinetrack.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

/**
 * Extends the default OidcUserService to log and inspect ID token claims.
 *
 * In production, this is where a database upsert would happen: look up or
 * create a CineTrack user record keyed on the "sub" claim, then store the
 * resolved internal ID somewhere the rest of the application can reach.
 */
@Service
public class CineTrackOidcUserService extends OidcUserService {

    private static final Logger log = LoggerFactory.getLogger(CineTrackOidcUserService.class);

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);

        String sub   = oidcUser.getSubject();
        String email = oidcUser.getEmail();
        String name  = oidcUser.getFullName();

        // Log for demo observability: replace with DB upsert in production.
        log.info("OIDC login: sub={}, email={}, name={}", sub, email, name);

        return oidcUser;
    }
}
