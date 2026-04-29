package com.example.security.customprovider;

import com.example.security.customprovider.model.DomainToken;
import com.example.security.customprovider.repository.DomainTokenRepository;
import com.example.security.customprovider.security.DomainTokenAuthenticationFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class CustomProviderSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private DomainTokenRepository domainTokenRepository;

    private String validUserToken;
    private String validAdminToken;

    @BeforeEach
    void setUp() {
        domainTokenRepository.deleteAll();

        validUserToken = "dtkn-test-user-valid";
        validAdminToken = "dtkn-test-admin-valid";

        Instant now = Instant.now();
        Instant future = now.plus(1, ChronoUnit.HOURS);

        domainTokenRepository.save(new DomainToken(validUserToken, "tokenuser", "USER", now, future));
        domainTokenRepository.save(new DomainToken(validAdminToken, "tokenadmin", "ADMIN", now, future));
    }

    @Nested
    @DisplayName("DB authentication (HTTP Basic via MockMvc user post-processor)")
    class DbAuthentication {

        @Test
        @DisplayName("valid USER credentials -> 200 on GET /api/resources")
        void validUserCredentialsReturns200() throws Exception {
            mockMvc.perform(get("/api/resources")
                            .with(user("user").roles("USER")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("valid ADMIN credentials -> 200 on GET /api/resources")
        void validAdminCredentialsReturns200() throws Exception {
            mockMvc.perform(get("/api/resources")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("Domain token authentication")
    class DomainTokenAuthentication {

        @Test
        @DisplayName("valid domain token -> 200 on GET /api/resources")
        void validDomainTokenReturns200() throws Exception {
            mockMvc.perform(get("/api/resources")
                            .header(DomainTokenAuthenticationFilter.DOMAIN_TOKEN_HEADER, validUserToken))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("invalid domain token -> 401 on GET /api/resources")
        void invalidDomainTokenReturns401() throws Exception {
            mockMvc.perform(get("/api/resources")
                            .header(DomainTokenAuthenticationFilter.DOMAIN_TOKEN_HEADER, "dtkn-does-not-exist"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("expired domain token -> 401 on GET /api/resources")
        void expiredDomainTokenReturns401() throws Exception {
            Instant past = Instant.now().minus(2, ChronoUnit.HOURS);
            String expiredToken = "dtkn-expired-token";
            domainTokenRepository.save(new DomainToken(expiredToken, "expireduser", "USER",
                    past.minus(1, ChronoUnit.HOURS), past));

            mockMvc.perform(get("/api/resources")
                            .header(DomainTokenAuthenticationFilter.DOMAIN_TOKEN_HEADER, expiredToken))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("No authentication")
    class NoAuthentication {

        @Test
        @DisplayName("no credentials -> 401 on GET /api/resources")
        void noAuthReturns401() throws Exception {
            mockMvc.perform(get("/api/resources"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("no credentials -> 401 on GET /api/resources/admin")
        void noAuthOnAdminEndpointReturns401() throws Exception {
            mockMvc.perform(get("/api/resources/admin"))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("Admin endpoint authorization")
    class AdminEndpointAuthorization {

        @Test
        @DisplayName("USER role -> 403 on GET /api/resources/admin")
        void userRoleOnAdminEndpointReturns403() throws Exception {
            mockMvc.perform(get("/api/resources/admin")
                            .with(user("user").roles("USER")))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("ADMIN role -> 200 on GET /api/resources/admin")
        void adminRoleOnAdminEndpointReturns200() throws Exception {
            mockMvc.perform(get("/api/resources/admin")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("domain token with ADMIN role -> 200 on GET /api/resources/admin")
        void adminDomainTokenOnAdminEndpointReturns200() throws Exception {
            mockMvc.perform(get("/api/resources/admin")
                            .header(DomainTokenAuthenticationFilter.DOMAIN_TOKEN_HEADER, validAdminToken))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("domain token with USER role -> 403 on GET /api/resources/admin")
        void userDomainTokenOnAdminEndpointReturns403() throws Exception {
            mockMvc.perform(get("/api/resources/admin")
                            .header(DomainTokenAuthenticationFilter.DOMAIN_TOKEN_HEADER, validUserToken))
                    .andExpect(status().isForbidden());
        }
    }
}
