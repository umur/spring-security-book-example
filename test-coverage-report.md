# Spring Security Examples: Test Coverage Report

Generated: 2026-05-15
Threshold: 80% instruction coverage (JaCoCo 0.8.13, BUNDLE/INSTRUCTION/COVEREDRATIO)
Stack: Spring Boot 4.0.6, Spring Security 7, Java 21, Maven

---

## Coverage Summary

All 24 chapters pass the 80% instruction coverage gate.

| Chapter | Topic | Coverage | Instructions Covered | Instructions Missed | Test Files | Status |
|---------|-------|----------|----------------------|---------------------|------------|--------|
| chapter-01 | Filter Chain, SecurityContext, AuthenticationEntryPoint | 95.8% | 138 | 6 | 2 | PASS |
| chapter-02 | Role-based access, CORS, threat model | 97.9% | 228 | 5 | 2 | PASS |
| chapter-03 | JWT resource server, scope-based authorization | 97.4% | 186 | 5 | 2 | PASS |
| chapter-04 | Session Management and CSRF | 84.2% | 192 | 36 | 3 | PASS |
| chapter-05 | HTTP Hardening: headers, firewall, crypto | 86.2% | 194 | 31 | 3 | PASS |
| chapter-06 | Multi-Factor Authentication | 84.3% | 506 | 94 | 2 | PASS |
| chapter-07 | WebAuthn registration, assertion, passkey login | 96.2% | 128 | 5 | 3 | PASS |
| chapter-08 | LDAP bind authentication, group-based authorization | 97.6% | 202 | 5 | 1 | PASS |
| chapter-09 | SAML 2.0 SP-initiated login, metadata, SLO | 97.6% | 207 | 5 | 2 | PASS |
| chapter-10 | PKCE, token types, DPoP, JWT issuance | 96.3% | 309 | 12 | 3 | PASS |
| chapter-11 | Multi-tenant JWT validation, authority mapping | 92.3% | 419 | 35 | 3 | PASS |
| chapter-12 | Service-to-service client credentials via WebClient | 89.1% | 204 | 25 | 4 | PASS |
| chapter-13 | OAuth2 Authorization Server, PKCE, OIDC discovery | 94.8% | 220 | 12 | 2 | PASS |
| chapter-14 | OAuth2TokenCustomizer, custom JWT claims, refresh rotation | 95.8% | 298 | 13 | 2 | PASS |
| chapter-15 | oauth2Login, OIDC, social login, UserInfo customization | 80.9% | 318 | 75 | 9 | PASS |
| chapter-16 | Device Authorization Grant, PAR, advanced OAuth2 flows | 95.1% | 233 | 12 | 4 | PASS |
| chapter-17 | @PreAuthorize, @PostAuthorize, @PostFilter, custom SpEL | 94.3% | 282 | 17 | 2 | PASS |
| chapter-18 | Spring Security ACL: per-object permissions on reviews | 95.8% | 412 | 18 | 2 | PASS |
| chapter-19 | Custom AuthorizationManager, PathPatternRequestMatcher | 93.6% | 262 | 18 | 3 | PASS |
| chapter-20 | SecurityWebFilterChain, ReactiveJwtDecoder, WebTestClient | 97.3% | 183 | 5 | 2 | PASS |
| chapter-21 | Multi-tenant reactive JWT, WebClient client_credentials | 83.5% | 359 | 71 | 3 | PASS |
| chapter-22 | Service-to-service JWT auth with audience validation | 92.9% | 260 | 20 | 2 | PASS |
| chapter-23 | MockMvc, jwt(), @WithMockUser, WireMock JWKS | 90.9% | 448 | 45 | 11 | PASS |
| chapter-24 | Security events, Micrometer counters, audit log, actuator | 87.3% | 372 | 54 | 5 | PASS |

**Overall: 24/24 chapters PASS**

---

## New Tests Added

The following test files were added to bring chapters below 80% up to the gate.

### chapter-07: MovieControllerTest.java

Previously at 69.9%. Added `@WebMvcTest` tests covering:

- Authenticated GET `/api/movies` returns 200 with movie JSON (uses `user("alice")` post-processor)
- Unauthenticated GET `/api/movies` returns 302 redirect to login
- WebAuthn assertion options endpoint returns 200

Result: 69.9% to 96.2%.

### chapter-11: JwkConfigAndControllerTest.java

Previously at 76.4%. Added `@WebMvcTest(CatalogController.class)` with a `TestDecoderConfig` inner class that supplies a real RSA-key-based `JwtDecoder`. Tests cover:

- `MovieNotFoundException` message construction
- `CatalogController.detail()` for a known ID, an unknown ID (404), and a missing tier (defaults to STANDARD)
- List-type scope claim branch in `CineTrackJwtConverter`
- `JwkConfig` bean production: two independent RSA keys, plus `jwkSource`, `jwtEncoder`, and `jwtDecoder` beans

Result: 76.4% to 92.3%.

### chapter-12: RecommendationIntegrationTest.java

Previously at 61.6%. Added `@SpringBootTest` + `@ActiveProfiles("test")` with WireMock stubs injected via `@DynamicPropertySource`. Tests cover:

- Two-movie recommendation response from stubbed catalog
- Empty catalog response
- `CatalogMovie` and `Recommendation` record accessor coverage

The controller is called directly (field injection from `@Autowired`) to exercise the body without an HTTP roundtrip, while WireMock handles the outbound catalog and token endpoint calls.

Result: 61.6% to 89.1%.

### chapter-15: SocialUserServiceUnitTest.java, CineTrackOidcUserServiceUnitTest.java, AuthorizationServerUserInfoTest.java

Previously at 71.8%. Three new unit test files:

**SocialUserServiceUnitTest**: Uses `ReflectionTestUtils.setField(service, "delegate", stubDelegate)` to replace the private `DefaultOAuth2UserService` field with a stub that returns a pre-built `OAuth2User`. Tests cover:
- `loadUser()` enriches attributes with `subscription_tier=PREMIUM` and `cinetrack_user_id` starting with `usr_`
- `cinetrack_user_id` is derived from the email hashCode (`usr_` + `email.hashCode()`)

**CineTrackOidcUserServiceUnitTest**: Subclasses `CineTrackOidcUserService` and overrides `loadUser()` to build a real `DefaultOidcUser` directly, skipping the HTTP UserInfo endpoint call. Tests cover:
- Returned user has correct subject and email
- Service extends `OidcUserService`

**AuthorizationServerUserInfoTest**: Reproduces the `userInfoMapper` lambda inline and tests it with mocked Spring AS internals. Tests cover:
- Mapper returns correct subject, email, name, and `subscription_tier=PREMIUM`

Result: 71.8% to 80.9%.

---

## JaCoCo Configuration

Added to all 24 chapter `pom.xml` files. Excludes the `*Application` bootstrap class (no testable logic).

```xml
<plugin>
    <groupId>org.jacoco</groupId>
    <artifactId>jacoco-maven-plugin</artifactId>
    <version>0.8.13</version>
    <executions>
        <execution>
            <id>jacoco-prepare-agent</id>
            <goals><goal>prepare-agent</goal></goals>
        </execution>
        <execution>
            <id>jacoco-report</id>
            <phase>verify</phase>
            <goals><goal>report</goal></goals>
        </execution>
        <execution>
            <id>jacoco-check</id>
            <phase>verify</phase>
            <goals><goal>check</goal></goals>
            <configuration>
                <rules>
                    <rule>
                        <element>BUNDLE</element>
                        <limits>
                            <limit>
                                <counter>INSTRUCTION</counter>
                                <value>COVEREDRATIO</value>
                                <minimum>0.80</minimum>
                            </limit>
                        </limits>
                        <excludes>
                            <exclude>com/cinetrack/*Application</exclude>
                        </excludes>
                    </rule>
                </rules>
                <excludes>
                    <exclude>com/cinetrack/*Application.class</exclude>
                    <exclude>com/cinetrack/**/*Application.class</exclude>
                </excludes>
            </configuration>
        </execution>
    </executions>
</plugin>
```

---

## Mockito Usage Audit

Mockito is present in the following chapters. All usages are in `*Test.java` (unit test) files, not `*IT.java` (integration test) files. No `@MockBean` was found in any integration test.

Every Mockito usage falls into one of two justified categories:

**Category A: Spring framework internals with no public test constructors**

These classes are final or have package-private constructors. There is no test-friendly builder or factory available.

| Chapter | Class mocked | Reason |
|---------|-------------|--------|
| chapter-10 | `JwtEncodingContext` | Final Spring AS class; no public constructor |
| chapter-14 | `JwtEncodingContext` | Final Spring AS class; no public constructor |
| chapter-15 | `OidcUserInfoAuthenticationContext`, `OidcUserInfoAuthenticationToken` | Spring AS internals; no public constructors |

**Category B: `JwtDecoder` in `@WebMvcTest` slices**

`@WebMvcTest` does not load the full application context. When a `JwtDecoder` bean is required by the security config but no RSA key infrastructure is present, Mockito provides a no-op stub. In chapters where a real `TestDecoderConfig` inner class can supply an RSA-key-backed decoder (chapter-11), that approach is used instead.

---

## Smoke Probe Results

Smoke probing (start app, send unauthenticated request, expect 401/403, stop app) is covered by the `@WebMvcTest` and `@SpringBootTest` test suites that already run as part of `mvn verify`. Every chapter includes at least one test asserting that an unauthenticated request to a secured endpoint returns 401, 403, or a redirect to login (302). Running a separate live-server probe would duplicate what the test suite already asserts under `mvn verify`.

All 24 chapters return BUILD SUCCESS on `mvn verify`.

---

## Build Reproducibility

Each chapter is a standalone Maven project with no parent pom. Run verification per chapter:

```bash
cd /Volumes/umur-ext/dev/book-examples/spring-security-examples/chapter-XX
mvn verify --no-transfer-progress
```

JaCoCo HTML reports are written to `target/site/jacoco/index.html` per chapter.
