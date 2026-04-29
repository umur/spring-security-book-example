package com.example.security.x509;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MockMvc tests for X.509 certificate authentication.
 *
 * Spring Security's {@code SecurityMockMvcRequestPostProcessors.x509(cert)}
 * post-processor populates the {@code javax.servlet.request.X509Certificate}
 * request attribute so the X.509 filter can authenticate without running a
 * full TLS handshake. Self-signed test certificates are generated in-memory
 * using BouncyCastle (pulled in transitively by spring-security-test).
 */
@SpringBootTest
@AutoConfigureMockMvc
class X509SecurityTest {

    @Autowired
    private MockMvc mockMvc;

    // -------------------------------------------------------------------------
    // Certificate factory helpers
    // -------------------------------------------------------------------------

    /**
     * Generates a self-signed RSA certificate with the given CN.
     * BouncyCastle is available on the test classpath via spring-security-test.
     */
    private static X509Certificate selfSignedCert(String cn) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        Instant now = Instant.now();
        var subject = new X500Name("CN=" + cn + ", O=Test, C=US");
        var certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.ONE,
                Date.from(now),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                kp.getPublic()
        );
        var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }

    // -------------------------------------------------------------------------
    // No certificate
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("No certificate provided")
    class NoCertificate {

        @Test
        @DisplayName("GET /api/profile without certificate returns 401")
        void noCertificateOnProfileReturns401() throws Exception {
            mockMvc.perform(get("/api/profile"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("GET /api/admin without certificate returns 401")
        void noCertificateOnAdminReturns401() throws Exception {
            mockMvc.perform(get("/api/admin"))
                    .andExpect(status().isUnauthorized());
        }
    }

    // -------------------------------------------------------------------------
    // Known USER certificate
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Known USER certificate (CN=client-user)")
    class UserCertificate {

        @Test
        @DisplayName("GET /api/profile with client-user cert returns 200 with CN in body")
        void userCertificateCanAccessProfile() throws Exception {
            X509Certificate cert = selfSignedCert("client-user");
            mockMvc.perform(get("/api/profile").with(x509(cert)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.cn").value("client-user"))
                    .andExpect(jsonPath("$.message").value("Authenticated via X.509 client certificate"));
        }

        @Test
        @DisplayName("GET /api/admin with client-user cert (USER-only) returns 403")
        void userCertificateCannotAccessAdmin() throws Exception {
            X509Certificate cert = selfSignedCert("client-user");
            mockMvc.perform(get("/api/admin").with(x509(cert)))
                    .andExpect(status().isForbidden());
        }
    }

    // -------------------------------------------------------------------------
    // Known ADMIN certificate
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Known ADMIN certificate (CN=client-admin)")
    class AdminCertificate {

        @Test
        @DisplayName("GET /api/profile with client-admin cert returns 200")
        void adminCertificateCanAccessProfile() throws Exception {
            X509Certificate cert = selfSignedCert("client-admin");
            mockMvc.perform(get("/api/profile").with(x509(cert)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.cn").value("client-admin"));
        }

        @Test
        @DisplayName("GET /api/admin with client-admin cert returns 200")
        void adminCertificateCanAccessAdmin() throws Exception {
            X509Certificate cert = selfSignedCert("client-admin");
            mockMvc.perform(get("/api/admin").with(x509(cert)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.cn").value("client-admin"))
                    .andExpect(jsonPath("$.message").value("Admin-only resource — certificate has ADMIN role"));
        }
    }

    // -------------------------------------------------------------------------
    // Unknown / unregistered certificate
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Unknown certificate CN")
    class UnknownCertificate {

        @Test
        @DisplayName("GET /api/profile with unknown CN returns 401")
        void unknownCertificateReturns401() throws Exception {
            X509Certificate cert = selfSignedCert("unknown-client");
            mockMvc.perform(get("/api/profile").with(x509(cert)))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("GET /api/admin with unknown CN returns 401")
        void unknownCertificateOnAdminReturns401() throws Exception {
            X509Certificate cert = selfSignedCert("attacker");
            mockMvc.perform(get("/api/admin").with(x509(cert)))
                    .andExpect(status().isUnauthorized());
        }
    }

    // -------------------------------------------------------------------------
    // service-a certificate
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Service certificate (CN=service-a)")
    class ServiceCertificate {

        @Test
        @DisplayName("GET /api/profile with service-a cert returns 200")
        void serviceACertificateCanAccessProfile() throws Exception {
            X509Certificate cert = selfSignedCert("service-a");
            mockMvc.perform(get("/api/profile").with(x509(cert)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.cn").value("service-a"));
        }

        @Test
        @DisplayName("GET /api/admin with service-a cert (no ADMIN role) returns 403")
        void serviceACertificateCannotAccessAdmin() throws Exception {
            X509Certificate cert = selfSignedCert("service-a");
            mockMvc.perform(get("/api/admin").with(x509(cert)))
                    .andExpect(status().isForbidden());
        }
    }

    // -------------------------------------------------------------------------
    // Role assertions using user() post-processor (config wire-up verification)
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Role-based access (via user post-processor)")
    class RoleBasedAccess {

        @Test
        @DisplayName("USER role cannot access /api/admin — 403")
        void userRoleCannotAccessAdmin() throws Exception {
            mockMvc.perform(get("/api/admin")
                            .with(user("any-user").roles("USER")))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("ADMIN role can access /api/admin — 200")
        void adminRoleCanAccessAdmin() throws Exception {
            mockMvc.perform(get("/api/admin")
                            .with(user("admin-user").roles("ADMIN")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("Authenticated user can access /api/profile — 200")
        void authenticatedUserCanAccessProfile() throws Exception {
            mockMvc.perform(get("/api/profile")
                            .with(user("client-user").roles("USER")))
                    .andExpect(status().isOk());
        }
    }
}
