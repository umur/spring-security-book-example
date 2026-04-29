package com.example.security.saml2;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Test-only Spring configuration that provides a fully programmatic
 * {@link RelyingPartyRegistrationRepository} — no XML metadata files and no
 * network calls to a live IdP.
 *
 * This bypasses the {@code application.yml} {@code metadata-uri: classpath:…}
 * property which would require OpenSAML to parse the IdP metadata XML at
 * startup. In tests we only need the registration to be wired so the
 * security filter chain initialises; the actual SAML authentication flow is
 * exercised by injecting a {@link org.springframework.security.saml2.provider.service.authentication.Saml2Authentication}
 * directly via {@code .with(authentication(...))}.
 */
@TestConfiguration
public class TestSaml2Config {

    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() throws Exception {
        // Load the SP signing certificate generated during the build
        X509Certificate spCert = loadCert("saml/sp-certificate.pem");
        Saml2X509Credential spSigningCredential =
                Saml2X509Credential.signing(loadPrivateKey(), spCert);
        Saml2X509Credential spVerificationCredential =
                Saml2X509Credential.verification(spCert);

        RelyingPartyRegistration registration = RelyingPartyRegistration
                .withRegistrationId("mock-idp")
                .entityId("http://localhost:8092/saml2/service-provider-metadata/mock-idp")
                .assertionConsumerServiceLocation(
                        "http://localhost:8092/login/saml2/sso/mock-idp")
                .assertionConsumerServiceBinding(Saml2MessageBinding.POST)
                .signingX509Credentials(creds -> creds.add(spSigningCredential))
                .decryptionX509Credentials(creds -> {})
                // AssertingParty (IdP) details — minimal stub for test context startup
                .assertingPartyMetadata(party -> party
                        .entityId("https://mock-idp.example.com/saml/metadata")
                        .singleSignOnServiceLocation(
                                "http://localhost:8092/mock-idp/saml2/sso")
                        .singleSignOnServiceBinding(Saml2MessageBinding.REDIRECT)
                        .verificationX509Credentials(creds ->
                                creds.add(spVerificationCredential))
                        .wantAuthnRequestsSigned(false)
                )
                .build();

        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

    private X509Certificate loadCert(String classpathResource) throws Exception {
        try (InputStream is = getClass().getClassLoader()
                .getResourceAsStream(classpathResource)) {
            if (is == null) {
                throw new IllegalStateException(
                        "Cannot find classpath resource: " + classpathResource);
            }
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(is);
        }
    }

    private java.security.PrivateKey loadPrivateKey() throws Exception {
        try (InputStream is = getClass().getClassLoader()
                .getResourceAsStream("saml/sp-private-key.pem")) {
            if (is == null) {
                throw new IllegalStateException(
                        "Cannot find classpath resource: saml/sp-private-key.pem");
            }
            String pem = new String(is.readAllBytes())
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] keyBytes = java.util.Base64.getDecoder().decode(pem);
            java.security.spec.PKCS8EncodedKeySpec spec =
                    new java.security.spec.PKCS8EncodedKeySpec(keyBytes);
            return java.security.KeyFactory.getInstance("RSA").generatePrivate(spec);
        }
    }
}
