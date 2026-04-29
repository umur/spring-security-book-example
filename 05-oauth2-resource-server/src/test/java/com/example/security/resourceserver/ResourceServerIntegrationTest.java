package com.example.security.resourceserver;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.util.Date;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
class ResourceServerIntegrationTest {

    // -----------------------------------------------------------------------
    // Infrastructure
    // -----------------------------------------------------------------------

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17-alpine");

    static WireMockServer wireMock;
    static RSAKey rsaKey;

    @BeforeAll
    static void startInfrastructure() throws Exception {
        rsaKey = new RSAKeyGenerator(2048).keyID("test-key-1").generate();

        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();

        // Serve the JWK Set so the resource server can verify tokens
        String jwkSet = "{\"keys\":[" + rsaKey.toPublicJWK().toJSONString() + "]}";
        wireMock.stubFor(get(urlEqualTo("/oauth2/jwks"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(jwkSet)));
    }

    @AfterAll
    static void stopInfrastructure() {
        if (wireMock != null) {
            wireMock.stop();
        }
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> "http://localhost:" + wireMock.port() + "/oauth2/jwks");
    }

    @Autowired
    private TestRestTemplate restTemplate;

    // -----------------------------------------------------------------------
    // JWT helpers
    // -----------------------------------------------------------------------

    private String buildToken(String subject, List<String> scopes, List<String> roles) throws Exception {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer("http://localhost:" + wireMock.port())
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3_600_000));

        if (scopes != null && !scopes.isEmpty()) {
            claims.claim("scope", String.join(" ", scopes));
        }
        if (roles != null && !roles.isEmpty()) {
            claims.claim("roles", roles);
        }

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                claims.build());
        jwt.sign(new RSASSASigner(rsaKey));
        return jwt.serialize();
    }

    private HttpHeaders bearerHeaders(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return headers;
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("GET /api/articles")
    class GetArticles {

        @Test
        @DisplayName("no token returns 401")
        void noTokenReturns401() {
            var response = restTemplate.getForEntity("/api/articles", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("valid JWT with scope=read returns 200 with article list")
        void validTokenWithReadScopeReturns200() throws Exception {
            String token = buildToken("reader", List.of("read"), null);
            var response = restTemplate.exchange(
                    "/api/articles", HttpMethod.GET,
                    new HttpEntity<>(bearerHeaders(token)), String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        @Test
        @DisplayName("expired or invalid token returns 401")
        void invalidTokenReturns401() {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth("this.is.not.a.valid.jwt");
            var response = restTemplate.exchange(
                    "/api/articles", HttpMethod.GET,
                    new HttpEntity<>(headers), String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    @Nested
    @DisplayName("POST /api/articles")
    class CreateArticle {

        @Test
        @DisplayName("JWT with scope=read cannot POST — returns 403")
        void readScopeCannotPost() throws Exception {
            String token = buildToken("reader", List.of("read"), null);
            HttpHeaders headers = bearerHeaders(token);
            headers.setContentType(MediaType.APPLICATION_JSON);
            var response = restTemplate.exchange(
                    "/api/articles", HttpMethod.POST,
                    new HttpEntity<>("{\"title\":\"X\",\"content\":\"Y\"}", headers),
                    String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }

        @Test
        @DisplayName("JWT with scope=write can POST — returns 201")
        void writeScopeCanPost() throws Exception {
            String token = buildToken("writer", List.of("write"), null);
            HttpHeaders headers = bearerHeaders(token);
            headers.setContentType(MediaType.APPLICATION_JSON);
            var response = restTemplate.exchange(
                    "/api/articles", HttpMethod.POST,
                    new HttpEntity<>("{\"title\":\"Integration Article\",\"content\":\"Real body\"}", headers),
                    String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            assertThat(response.getBody()).contains("Integration Article");
            assertThat(response.getBody()).contains("writer");
        }

        @Test
        @DisplayName("full flow: write token creates article, read token retrieves it")
        void fullFlow() throws Exception {
            String writeToken = buildToken("author", List.of("write"), null);
            HttpHeaders writeHeaders = bearerHeaders(writeToken);
            writeHeaders.setContentType(MediaType.APPLICATION_JSON);

            var createResponse = restTemplate.exchange(
                    "/api/articles", HttpMethod.POST,
                    new HttpEntity<>("{\"title\":\"Full Flow Article\",\"content\":\"Content\"}", writeHeaders),
                    String.class);
            assertThat(createResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            assertThat(createResponse.getBody()).contains("Full Flow Article");

            String readToken = buildToken("reader", List.of("read"), null);
            var listResponse = restTemplate.exchange(
                    "/api/articles", HttpMethod.GET,
                    new HttpEntity<>(bearerHeaders(readToken)), String.class);
            assertThat(listResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(listResponse.getBody()).contains("Full Flow Article");
        }
    }

    @Nested
    @DisplayName("Role-based access via custom roles claim")
    class RoleBasedAccess {

        @Test
        @DisplayName("JWT with roles=[USER] can read articles")
        void userRoleCanRead() throws Exception {
            String token = buildToken("user1", null, List.of("USER"));
            var response = restTemplate.exchange(
                    "/api/articles", HttpMethod.GET,
                    new HttpEntity<>(bearerHeaders(token)), String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        @Test
        @DisplayName("JWT with roles=[ADMIN] can create articles")
        void adminRoleCanCreate() throws Exception {
            String token = buildToken("admin1", null, List.of("ADMIN"));
            HttpHeaders headers = bearerHeaders(token);
            headers.setContentType(MediaType.APPLICATION_JSON);
            var response = restTemplate.exchange(
                    "/api/articles", HttpMethod.POST,
                    new HttpEntity<>("{\"title\":\"Admin Post\",\"content\":\"Body\"}", headers),
                    String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        }
    }
}
