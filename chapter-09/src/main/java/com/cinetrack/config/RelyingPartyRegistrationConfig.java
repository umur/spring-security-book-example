package com.cinetrack.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Builds the SP {@link RelyingPartyRegistration} for CineTrack's SAML2 integration.
 *
 * <p>The registration ID is {@code cinetrack-okta}. This ID appears in all
 * auto-generated SAML2 URLs:
 * <ul>
 *   <li>ACS:      {@code /login/saml2/sso/cinetrack-okta}</li>
 *   <li>Metadata: {@code /saml2/service-provider-metadata/cinetrack-okta}</li>
 *   <li>SLO:      {@code /logout/saml2/slo}</li>
 *   <li>Redirect: {@code /saml2/authenticate/cinetrack-okta}</li>
 * </ul>
 *
 * <p>The SP signing credential is loaded from the classpath keystore
 * {@code cinetrack-sp.p12}. The IdP is configured inline using a hardcoded
 * SSO URL and the SP's own certificate as a stand-in for the IdP's verification
 * key: sufficient to start the application and exercise the redirect flow
 * without parsing a live IdP metadata document at boot.
 */
@Configuration
public class RelyingPartyRegistrationConfig {

    private static final String REGISTRATION_ID    = "cinetrack-okta";
    private static final String KEYSTORE_PATH      = "cinetrack-sp.p12";
    private static final String KEYSTORE_PASS      = "changeit";
    private static final String KEY_ALIAS          = "cinetrack-sp";
    private static final String IDP_ENTITY_ID      = "http://localhost:8080/test-idp";
    private static final String IDP_SSO_URL        = "http://localhost:8080/test-idp/sso";

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() throws Exception {
        Saml2X509Credential signingCredential = spSigningCredential();
        Saml2X509Credential verificationCredential = idpVerificationCredential();

        RelyingPartyRegistration registration = RelyingPartyRegistration
                .withRegistrationId(REGISTRATION_ID)
                .entityId("http://localhost:8080/saml2/service-provider-metadata/" + REGISTRATION_ID)
                .assertionConsumerServiceLocation(
                        "http://localhost:8080/login/saml2/sso/" + REGISTRATION_ID)
                .assertionConsumerServiceBinding(Saml2MessageBinding.POST)
                .signingX509Credentials(creds -> creds.add(signingCredential))
                .assertingPartyMetadata(party -> party
                        .entityId(IDP_ENTITY_ID)
                        .singleSignOnServiceLocation(IDP_SSO_URL)
                        .singleSignOnServiceBinding(Saml2MessageBinding.POST)
                        .wantAuthnRequestsSigned(false)
                        .verificationX509Credentials(creds -> creds.add(verificationCredential))
                )
                .build();

        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

    /**
     * Loads the SP private key and self-signed certificate from the PKCS12
     * keystore bundled on the classpath. Generated once with:
     * <pre>
     *   keytool -genkeypair -alias cinetrack-sp -keyalg RSA -keysize 2048 \
     *     -validity 3650 -storetype PKCS12 \
     *     -storepass changeit -keypass changeit \
     *     -dname "CN=CineTrack SP,O=CineTrack,C=US" \
     *     -keystore src/main/resources/cinetrack-sp.p12
     * </pre>
     */
    private Saml2X509Credential spSigningCredential() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(KEYSTORE_PATH)) {
            ks.load(is, KEYSTORE_PASS.toCharArray());
        }
        PrivateKey privateKey = (PrivateKey) ks.getKey(KEY_ALIAS, KEYSTORE_PASS.toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate(KEY_ALIAS);
        return Saml2X509Credential.signing(privateKey, certificate);
    }

    /**
     * Reuses the SP's own certificate as the IdP verification credential. In a
     * real deployment this would be the IdP's public signing certificate, fetched
     * from the IdP's metadata. Tests in this chapter only exercise the redirect
     * flow (no signed assertion is sent back), so any valid X.509 cert works.
     */
    private Saml2X509Credential idpVerificationCredential() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(KEYSTORE_PATH)) {
            ks.load(is, KEYSTORE_PASS.toCharArray());
        }
        X509Certificate certificate = (X509Certificate) ks.getCertificate(KEY_ALIAS);
        return Saml2X509Credential.verification(certificate);
    }
}
