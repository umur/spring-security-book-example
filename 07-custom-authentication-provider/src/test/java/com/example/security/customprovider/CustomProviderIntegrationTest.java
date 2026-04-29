package com.example.security.customprovider;

import com.example.security.customprovider.controller.TokenController.TokenResponse;
import com.example.security.customprovider.security.DomainTokenAuthenticationFilter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
class CustomProviderIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17-alpine");

    @DynamicPropertySource
    static void configureDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
    }

    @Autowired
    private TestRestTemplate restTemplate;

    @Nested
    @DisplayName("DB authentication (HTTP Basic)")
    class DbAuthenticationIT {

        @Test
        @DisplayName("admin with correct password gets 200 on GET /api/resources")
        void adminWithCorrectPasswordGets200() {
            var response = restTemplate
                    .withBasicAuth("admin", "admin")
                    .getForEntity("/api/resources", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).contains("Resource Alpha");
        }

        @Test
        @DisplayName("user with correct password gets 200 on GET /api/resources")
        void userWithCorrectPasswordGets200() {
            var response = restTemplate
                    .withBasicAuth("user", "user")
                    .getForEntity("/api/resources", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        @Test
        @DisplayName("wrong password returns 401")
        void wrongPasswordReturns401() {
            var response = restTemplate
                    .withBasicAuth("admin", "wrongpassword")
                    .getForEntity("/api/resources", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("unauthenticated request returns 401")
        void unauthenticatedReturns401() {
            var response = restTemplate.getForEntity("/api/resources", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    @Nested
    @DisplayName("Domain token authentication end-to-end")
    class DomainTokenAuthenticationIT {

        @Test
        @DisplayName("login via HTTP Basic, generate token, access resource with domain token")
        void loginGenerateTokenAndAccessWithToken() {
            // Step 1: Authenticate via HTTP Basic and generate a domain token
            var tokenResponse = restTemplate
                    .withBasicAuth("user", "user")
                    .postForEntity("/api/tokens", HttpEntity.EMPTY, TokenResponse.class);

            assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            assertThat(tokenResponse.getBody()).isNotNull();
            String domainToken = tokenResponse.getBody().token();
            assertThat(domainToken).startsWith("dtkn-");

            // Step 2: Access protected resource using the domain token (no Basic Auth)
            var headers = new HttpHeaders();
            headers.set(DomainTokenAuthenticationFilter.DOMAIN_TOKEN_HEADER, domainToken);
            var resourceResponse = restTemplate.exchange(
                    "/api/resources",
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class
            );

            assertThat(resourceResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(resourceResponse.getBody()).contains("Resource Alpha");
        }

        @Test
        @DisplayName("admin generates token and accesses admin endpoint with domain token")
        void adminGeneratesTokenAndAccessesAdminEndpoint() {
            // Step 1: Admin authenticates and generates a domain token
            var tokenResponse = restTemplate
                    .withBasicAuth("admin", "admin")
                    .postForEntity("/api/tokens", HttpEntity.EMPTY, TokenResponse.class);

            assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            String adminToken = tokenResponse.getBody().token();

            // Step 2: Use domain token to access admin-only endpoint
            var headers = new HttpHeaders();
            headers.set(DomainTokenAuthenticationFilter.DOMAIN_TOKEN_HEADER, adminToken);
            var adminResponse = restTemplate.exchange(
                    "/api/resources/admin",
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class
            );

            assertThat(adminResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(adminResponse.getBody()).contains("Admin-only resource");
        }

        @Test
        @DisplayName("invalid domain token returns 401")
        void invalidDomainTokenReturns401() {
            var headers = new HttpHeaders();
            headers.set(DomainTokenAuthenticationFilter.DOMAIN_TOKEN_HEADER, "dtkn-bogus-token-xyz");
            var response = restTemplate.exchange(
                    "/api/resources",
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class
            );
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("user domain token cannot access admin endpoint - returns 403")
        void userDomainTokenCannotAccessAdminEndpoint() {
            // Generate a USER-level domain token
            var tokenResponse = restTemplate
                    .withBasicAuth("user", "user")
                    .postForEntity("/api/tokens", HttpEntity.EMPTY, TokenResponse.class);
            assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            String userToken = tokenResponse.getBody().token();

            // Attempt admin endpoint
            var headers = new HttpHeaders();
            headers.set(DomainTokenAuthenticationFilter.DOMAIN_TOKEN_HEADER, userToken);
            var response = restTemplate.exchange(
                    "/api/resources/admin",
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class
            );

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }
    }

    @Nested
    @DisplayName("Both auth methods work end-to-end")
    class BothAuthMethodsIT {

        @Test
        @DisplayName("HTTP Basic and domain token both access the same resource")
        void bothMethodsAccessSameResource() {
            // DB auth
            var dbResponse = restTemplate
                    .withBasicAuth("user", "user")
                    .getForEntity("/api/resources", String.class);
            assertThat(dbResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(dbResponse.getBody()).contains("Resource Alpha");

            // Generate domain token
            var tokenResponse = restTemplate
                    .withBasicAuth("user", "user")
                    .postForEntity("/api/tokens", HttpEntity.EMPTY, TokenResponse.class);
            assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            String domainToken = tokenResponse.getBody().token();

            // Domain token auth
            var headers = new HttpHeaders();
            headers.set(DomainTokenAuthenticationFilter.DOMAIN_TOKEN_HEADER, domainToken);
            var tokenAuthResponse = restTemplate.exchange(
                    "/api/resources",
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class
            );
            assertThat(tokenAuthResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(tokenAuthResponse.getBody()).contains("Resource Alpha");
        }
    }
}
