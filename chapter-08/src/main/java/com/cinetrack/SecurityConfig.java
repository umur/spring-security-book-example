package com.cinetrack;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

/**
 * Enterprise LDAP authentication for CineTrack.
 *
 * <h2>Authentication flow</h2>
 * <ol>
 *   <li>HTTP Basic credentials arrive on the request.</li>
 *   <li>{@link LdapAuthenticationProvider} delegates to {@link BindAuthenticator},
 *       which binds to the embedded UnboundID server using the DN pattern
 *       {@code uid={0},ou=people,dc=cinetrack,dc=io}.</li>
 *   <li>{@link DefaultLdapAuthoritiesPopulator} searches
 *       {@code ou=groups,dc=cinetrack,dc=io} for {@code groupOfNames} entries
 *       whose {@code member} attribute contains the user DN. Each matching
 *       {@code cn} becomes a {@code GrantedAuthority}:
 *       {@code cn=viewers → ROLE_VIEWERS}, {@code cn=admins → ROLE_ADMINS}.</li>
 * </ol>
 *
 * <h2>Authorization</h2>
 * <ul>
 *   <li>{@code /api/movies/**}: {@code ROLE_VIEWERS}</li>
 *   <li>{@code /api/admin/**}: {@code ROLE_ADMINS}</li>
 * </ul>
 *
 * <p>Note: In Spring Security 7 the legacy
 * {@code AuthenticationManagerBuilder#ldapAuthentication()} fluent API was
 * removed. Configure LDAP authentication by wiring
 * {@link LdapAuthenticationProvider} as a bean and exposing it through a
 * {@link ProviderManager}, then registering that manager with
 * {@code HttpSecurity#authenticationManager(AuthenticationManager)}.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authenticationManager(ldapAuthenticationManager())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/admin/**").hasRole("ADMINS")
                .requestMatchers("/api/movies/**").hasRole("VIEWERS")
                .anyRequest().authenticated()
            )
            .httpBasic(basic -> {});

        return http.build();
    }

    /**
     * Wires the LDAP bind authenticator and authorities populator into a
     * {@link ProviderManager} so Spring Security can find them through the
     * standard {@link AuthenticationManager} contract.
     */
    @Bean
    public AuthenticationManager ldapAuthenticationManager() {
        return new ProviderManager(List.of(ldapAuthenticationProvider()));
    }

    @Bean
    public LdapAuthenticationProvider ldapAuthenticationProvider() {
        var provider = new LdapAuthenticationProvider(
                bindAuthenticator(),
                ldapAuthoritiesPopulator()
        );
        return provider;
    }

    /**
     * Performs a simple bind using the DN pattern
     * {@code uid={0},ou=people,dc=cinetrack,dc=io}.
     * No manager credentials needed: anonymous searches work on the
     * embedded UnboundID server for the bind-attempt step.
     */
    @Bean
    public BindAuthenticator bindAuthenticator() {
        var authenticator = new BindAuthenticator(contextSource());
        authenticator.setUserDnPatterns(new String[]{"uid={0},ou=people"});
        return authenticator;
    }

    /**
     * After a successful bind, searches {@code ou=groups} for
     * {@code groupOfNames} entries that list the user's DN as a member.
     * The group's {@code cn} attribute becomes the role name
     * (prefix {@code ROLE_} is added automatically).
     */
    @Bean
    public DefaultLdapAuthoritiesPopulator ldapAuthoritiesPopulator() {
        var populator = new DefaultLdapAuthoritiesPopulator(
                contextSource(), "ou=groups");
        populator.setGroupRoleAttribute("cn");
        populator.setGroupSearchFilter("(member={0})");
        return populator;
    }

    /**
     * Connects to the embedded UnboundID LDAP server started by
     * {@link EmbeddedLdapConfig} on port 8389.
     */
    @Bean
    public DefaultSpringSecurityContextSource contextSource() {
        var source = new DefaultSpringSecurityContextSource(
                "ldap://localhost:8389/dc=cinetrack,dc=io");
        source.setUserDn("cn=admin,dc=cinetrack,dc=io");
        source.setPassword("secret");
        return source;
    }
}
