package com.cinetrack;

import com.cinetrack.config.RelyingPartyRegistrationConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

/**
 * SAML2 security configuration for CineTrack.
 *
 * <p>SP-initiated SSO flow:
 * <ol>
 *   <li>Unauthenticated request hits {@code /api/movies}.</li>
 *   <li>Spring Security redirects to {@code /saml2/authenticate/cinetrack-okta}.</li>
 *   <li>An {@code AuthnRequest} is POSTed to the IdP SSO endpoint.</li>
 *   <li>IdP authenticates the user and POSTs the {@code SAMLResponse} to the ACS
 *       ({@code /login/saml2/sso/cinetrack-okta}).</li>
 *   <li>Spring Security validates the assertion, creates a {@code Saml2AuthenticatedPrincipal},
 *       and establishes a session.</li>
 * </ol>
 *
 * <p>SP metadata is served at
 * {@code /saml2/service-provider-metadata/cinetrack-okta} so the IdP can
 * import it without manual certificate management.
 *
 * <p>The {@link RelyingPartyRegistrationRepository} bean is provided by
 * {@link RelyingPartyRegistrationConfig}.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final RelyingPartyRegistrationRepository registrationRepository;

    public SecurityConfig(RelyingPartyRegistrationRepository registrationRepository) {
        this.registrationRepository = registrationRepository;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/saml2/**", "/login/saml2/**").permitAll()
                .requestMatchers("/api/movies/**").authenticated()
                .anyRequest().authenticated()
            )
            .saml2Login(saml2 -> saml2
                .relyingPartyRegistrationRepository(registrationRepository)
            )
            .saml2Logout(Customizer.withDefaults())
            .saml2Metadata(Customizer.withDefaults());

        return http.build();
    }
}
