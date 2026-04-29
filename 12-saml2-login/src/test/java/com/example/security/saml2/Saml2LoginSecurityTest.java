package com.example.security.saml2;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * SAML 2.0 login security tests.
 *
 * Testing strategy for SAML2 in Spring Security 7:
 *
 * NOTE: The .with(saml2Login()) post-processor was REMOVED in Spring Security 7.
 * The correct approach is to construct a Saml2Authentication directly and inject
 * it via .with(authentication(...)).
 *
 * Patterns demonstrated:
 *
 * 1. Unauthenticated redirect — verifies the security filter chain redirects any
 *    protected path to the SAML login endpoint (/saml2/authenticate/{registrationId}).
 *
 * 2. SP Metadata endpoint — verifies Spring Security auto-generates the SP metadata
 *    XML at /saml2/metadata/{registrationId}. This endpoint must be publicly accessible
 *    so that identity providers can fetch it before any user session exists.
 *
 * 3. Authenticated via .with(authentication(saml2Auth(...))) — constructs a
 *    DefaultSaml2AuthenticatedPrincipal with the desired attributes and wraps it
 *    in a Saml2Authentication, then injects it directly into the SecurityContext via
 *    the MockMvc authentication() post-processor.
 *
 * 4. SAML login initiation — verifies that GET /saml2/authenticate/{registrationId}
 *    produces a redirect (to the configured IdP SSO URL).
 *
 * Spring Boot 4 / Spring Security 7 conventions:
 *   - @AutoConfigureMockMvc from org.springframework.boot.webmvc.test.autoconfigure
 *   - .with(authentication(...)) replaces the removed .with(saml2Login())
 *   - @SpringBootTest loads the full context including the SAML2 filter chain
 *   - @Import(TestSaml2Config.class) provides a programmatic RelyingPartyRegistrationRepository
 *     so no IdP metadata XML needs to be parsed at startup
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestSaml2Config.class)
@TestPropertySource(properties = {
        // Disable the application.yml metadata-uri so Spring Boot auto-config
        // does not try to parse the classpath XML through OpenSAML at startup.
        // TestSaml2Config provides the repository bean programmatically instead.
        "spring.security.saml2.relyingparty.registration.mock-idp.assertingparty.metadata-uri="
})
class Saml2LoginSecurityTest {

    @Autowired
    MockMvc mockMvc;

    // =========================================================================
    // Helper — builds a Saml2Authentication for use in tests
    // =========================================================================

    /**
     * Constructs a {@link Saml2Authentication} backed by a
     * {@link DefaultSaml2AuthenticatedPrincipal} with the given name and attributes.
     *
     * This is the Spring Security 7 replacement for the removed
     * {@code .with(saml2Login())} post-processor.
     *
     * @param nameId     the SAML NameID (principal name)
     * @param attributes SAML assertion attributes — each value is a List
     * @param roles      granted roles (without ROLE_ prefix)
     */
    private static Saml2Authentication saml2Auth(String nameId,
                                                  Map<String, List<Object>> attributes,
                                                  String... roles) {
        DefaultSaml2AuthenticatedPrincipal principal =
                new DefaultSaml2AuthenticatedPrincipal(nameId, attributes);
        principal.setRelyingPartyRegistrationId("mock-idp");

        List<SimpleGrantedAuthority> authorities = java.util.Arrays.stream(roles)
                .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                .toList();

        // The samlResponse string is only needed for serialization; in tests
        // a placeholder is sufficient since no actual SAML XML processing occurs.
        return new Saml2Authentication(principal, "mock-saml-response", authorities);
    }

    /** Convenience overload with default USER role and no attributes. */
    private static Saml2Authentication saml2Auth(String nameId) {
        return saml2Auth(nameId, Map.of(), "USER");
    }

    /** Convenience overload with attributes and default USER role. */
    private static Saml2Authentication saml2Auth(String nameId,
                                                  Map<String, List<Object>> attributes) {
        return saml2Auth(nameId, attributes, "USER");
    }

    // =========================================================================
    // Unauthenticated access — must redirect to SAML login
    // =========================================================================

    @Nested
    @DisplayName("Unauthenticated access")
    class UnauthenticatedAccess {

        @Test
        @DisplayName("GET /dashboard without auth redirects to login page")
        void dashboardRedirectsToSamlLogin() throws Exception {
            // Spring Security redirects unauthenticated users to the configured
            // loginPage ("/login"), not directly to /saml2/authenticate.
            // The login page then presents the SAML IdP link.
            mockMvc.perform(get("/dashboard"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(header().string("Location",
                            containsString("/login")));
        }

        @Test
        @DisplayName("GET / without auth redirects")
        void rootRedirects() throws Exception {
            mockMvc.perform(get("/"))
                    .andExpect(status().is3xxRedirection());
        }
    }

    // =========================================================================
    // SP Metadata endpoint — publicly accessible, no auth required
    // =========================================================================

    @Nested
    @DisplayName("SP Metadata endpoint")
    class MetadataEndpoint {

        @Test
        @DisplayName("GET /saml2/metadata/mock-idp returns 200 with XML content")
        void spMetadataIsPubliclyAccessible() throws Exception {
            mockMvc.perform(get("/saml2/metadata/mock-idp"))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType("application/samlmetadata+xml;charset=UTF-8"));
        }

        @Test
        @DisplayName("SP metadata contains EntityDescriptor element")
        void spMetadataContainsEntityDescriptor() throws Exception {
            mockMvc.perform(get("/saml2/metadata/mock-idp"))
                    .andExpect(status().isOk())
                    .andExpect(content().string(containsString("EntityDescriptor")));
        }

        @Test
        @DisplayName("SP metadata contains AssertionConsumerService")
        void spMetadataContainsAcsUrl() throws Exception {
            mockMvc.perform(get("/saml2/metadata/mock-idp"))
                    .andExpect(status().isOk())
                    .andExpect(content().string(containsString("AssertionConsumerService")));
        }

        @Test
        @DisplayName("SP metadata entity ID matches configured value")
        void spMetadataEntityId() throws Exception {
            mockMvc.perform(get("/saml2/metadata/mock-idp"))
                    .andExpect(status().isOk())
                    .andExpect(content().string(
                            containsString("saml2/service-provider-metadata/mock-idp")));
        }
    }

    // =========================================================================
    // Authenticated via .with(authentication(saml2Auth(...)))
    //
    // Spring Security 7 removed .with(saml2Login()). The correct approach is to
    // build a Saml2Authentication directly and inject it via authentication().
    // =========================================================================

    @Nested
    @DisplayName("Authenticated via .with(authentication(saml2Auth(...)))")
    class AuthenticatedViaSaml2Auth {

        @Test
        @DisplayName("SAML2-authenticated user can access /dashboard — returns 200")
        void authenticatedUserAccessesDashboard() throws Exception {
            mockMvc.perform(get("/dashboard")
                            .with(authentication(saml2Auth("alice"))))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("SAML2-authenticated user with attributes can access /dashboard")
        void authenticatedUserWithAttributesAccessesDashboard() throws Exception {
            Map<String, List<Object>> attrs = Map.of(
                    "email", List.of("alice@example.com"),
                    "displayName", List.of("Alice Smith")
            );
            mockMvc.perform(get("/dashboard")
                            .with(authentication(saml2Auth("alice", attrs))))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.nameId").value("alice"));
        }

        @Test
        @DisplayName("SAML2 principal with email attribute exposes email in response")
        void saml2PrincipalEmailInResponse() throws Exception {
            Map<String, List<Object>> attrs = Map.of(
                    "email", List.of("saml-user@example.com")
            );
            mockMvc.perform(get("/dashboard")
                            .with(authentication(saml2Auth("saml-user", attrs))))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.email").value("saml-user@example.com"));
        }

        @Test
        @DisplayName("SAML2 principal displayName is used as display name")
        void saml2DisplayNameFromAttribute() throws Exception {
            Map<String, List<Object>> attrs = Map.of(
                    "displayName", List.of("Bob SAML"),
                    "email", List.of("bob@example.com")
            );
            mockMvc.perform(get("/dashboard")
                            .with(authentication(saml2Auth("bob", attrs))))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.displayName").value("Bob SAML"));
        }

        @Test
        @DisplayName("SAML2 attributes map is included in response")
        void saml2AttributesMapInResponse() throws Exception {
            Map<String, List<Object>> attrs = Map.of(
                    "department", List.of("Engineering"),
                    "role", List.of("developer")
            );
            mockMvc.perform(get("/dashboard")
                            .with(authentication(saml2Auth("dev-user", attrs))))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.attributes").isMap());
        }

        @Test
        @DisplayName("SAML2 auth with ADMIN role can access /dashboard")
        void saml2AuthWithAdminRole() throws Exception {
            mockMvc.perform(get("/dashboard")
                            .with(authentication(
                                    saml2Auth("admin",
                                            Map.of("email", List.of("admin@idp.example.com")),
                                            "ADMIN"))))
                    .andExpect(status().isOk());
        }
    }

    // =========================================================================
    // SAML login initiation — redirect to IdP
    // =========================================================================

    @Nested
    @DisplayName("SAML login initiation")
    class SamlLoginInitiation {

        @Test
        @DisplayName("GET /saml2/authenticate/mock-idp redirects to IdP SSO URL")
        void samlAuthenticateRedirectsToIdp() throws Exception {
            mockMvc.perform(get("/saml2/authenticate/mock-idp"))
                    .andExpect(status().is3xxRedirection());
        }
    }
}
