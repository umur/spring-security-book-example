# Spring Security Examples

## Overview
Multi-module Maven project: each module is a self-contained Spring Boot 4 app demonstrating one Spring Security 7 feature.

## Tech Stack
- **Spring Boot 4.0.4** / **Spring Security 7.0.4** / **Java 21** / **Maven 3.8+**
- Lombok for boilerplate reduction, Java records for DTOs
- H2 for local dev, PostgreSQL via Testcontainers for integration tests

## Build & Run
```bash
mvn clean verify                        # Build all modules
mvn clean test -pl 01-form-login        # Test single module
mvn spring-boot:run -pl 01-form-login   # Run single module
```

## Conventions

### Package Structure
`com.example.security.<featurename>`: e.g., `com.example.security.formlogin`

### Architecture
- **Controllers are extremely thin**: no logic, no conditionals, no repository calls
- Controllers only: accept request → call service → return response
- **All business logic in service layer**: even simple operations go through a service
- Java records for DTOs, Lombok for entities

### Controller Rules (strict: no exceptions)
Controllers MAY only contain:
- Class-level annotations (`@RestController`, `@RequestMapping`, `@RequiredArgsConstructor`, etc.)
- Method-level REST annotations (`@GetMapping`, `@PostMapping`, `@PutMapping`, `@DeleteMapping`, `@PatchMapping`, `@ResponseStatus`)
- Parameter annotations (`@RequestBody`, `@PathVariable`, `@RequestParam`, `@AuthenticationPrincipal`, etc.)
- A single service call per method
- A `return` statement

Controllers MUST NOT contain:
- `try-catch` blocks: use `@ControllerAdvice` for exception mapping
- Logging (`log.*`, `logger.*`, `@Slf4j`, `System.out.*`)
- Conditionals (`if`, `switch`, ternary `?:`)
- Loops or streams (`for`, `while`, `.stream()`, `.map()`, `.filter()`)
- Data transformation or string manipulation
- Direct repository calls
- Multiple service calls per method
- Helper/private methods with logic
- `instanceof` checks or casting
- Business object construction (entities, value objects)

Exception handling belongs exclusively in `@ControllerAdvice` classes: one per module, named `GlobalExceptionHandler`.

### Security Config Pattern (Spring Security 7)
- `SecurityFilterChain` as `@Bean`: never extend deprecated adapters
- Lambda DSL: no `.and()` chaining
- `PasswordEncoderFactories.createDelegatingPasswordEncoder()` as default encoder
- `{bcrypt}` prefixed passwords in seed data

### CRITICAL: Spring Boot 4 Import Changes
These packages MOVED in Boot 4. Using old imports will cause compilation failures:

| Class | Boot 4 Import |
|-------|--------------|
| `@AutoConfigureMockMvc` | `org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc` |
| `@WebMvcTest` | `org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest` |
| `TestRestTemplate` | `org.springframework.boot.resttestclient.TestRestTemplate` |
| `@AutoConfigureTestRestTemplate` | `org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate` |
| `@MockitoBean` (replaces `@MockBean`) | `org.springframework.test.context.bean.override.mockito.MockitoBean` |

### CRITICAL: @WithMockUser Does NOT Work in Boot 4
Use `.with(user("name").roles("ROLE"))` request post-processor instead:
```java
mockMvc.perform(get("/api/resource").with(user("alice").roles("USER")))
```

### Testing (TDD)
- **Unit tests** (`*Test.java`): `@SpringBootTest` + `@AutoConfigureMockMvc` with `.with(user(...))` post-processors
- **Integration tests** (`*IntegrationTest.java`): `@SpringBootTest(webEnvironment = RANDOM_PORT)` + `@AutoConfigureTestRestTemplate` + `@Testcontainers`, no mocking, PostgreSQL container
- Write tests FIRST, then implement

### Required Test Dependencies (per module POM)
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-restclient</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-resttestclient</artifactId>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-webmvc-test</artifactId>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>org.testcontainers</groupId>
    <artifactId>postgresql</artifactId>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>org.postgresql</groupId>
    <artifactId>postgresql</artifactId>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>org.testcontainers</groupId>
    <artifactId>junit-jupiter</artifactId>
    <scope>test</scope>
</dependency>
```

### Port Assignments
| Module | Port |
|--------|------|
| 01-form-login | 8081 |
| 02-http-basic | 8082 |
| 03-jwt-authentication | 8083 |
| 04-oauth2-login | 8084 |
| 05-oauth2-resource-server | 8085 |
| 06-ldap-authentication | 8086 |
| 07-custom-authentication-provider | 8087 |
| 08-api-key-authentication | 8088 |
| 09-x509-certificate | 8089 |
| 10-multi-factor-auth | 8090 |
| 11-remember-me | 8091 |
| 12-saml2-login | 8092 |
| 13-role-based-authorization | 8093 |
| 14-method-security | 8094 |
| 28-password-encoding | 8108 |

## Module Status

### Wave 1 (Foundation): COMPLETE
- [x] common
- [x] 01-form-login (10 tests)
- [x] 02-http-basic (13 tests)
- [x] 28-password-encoding (29 tests)
- [x] 13-role-based-authorization (26 tests)

### Wave 2 (Core Auth): COMPLETE
- [x] 03-jwt-authentication (30 tests)
- [x] 07-custom-authentication-provider (26 tests)
- [x] 08-api-key-authentication (16 tests)
- [x] 11-remember-me (11 tests)
- [x] 14-method-security (26 tests)

### Additional Boot 4 Discoveries (Wave 2)
- Jackson 3 uses `tools.jackson.*` package, NOT `com.fasterxml.jackson.*`
- `DaoAuthenticationProvider` no-arg constructor removed in Security 7: must pass `UserDetailsService` to constructor
- `AbstractAuthenticationToken(null)` is ambiguous: use `Collections.emptyList()` instead
- Surefire fork timeout with Testcontainers: set `forkedProcessExitTimeoutInSeconds` to 60 in parent POM

### Wave 3 (Protection & Session): COMPLETE
- [x] 17-csrf-protection (20 tests)
- [x] 18-cors-configuration (15 tests)
- [x] 19-security-headers (21 tests)
- [x] 20-session-management (13 tests)
- [x] 29-custom-filter-chain (23 tests)

### Wave 4 (OAuth2 & Advanced Auth): COMPLETE
- [x] 04-oauth2-login (11 tests)
- [x] 05-oauth2-resource-server (19 tests)
- [x] 06-ldap-authentication (13 tests)
- [x] 10-multi-factor-auth (15 tests)
- [x] 30-microservice-security (13 tests)

### Wave 5 (Advanced Features): COMPLETE
- [x] 15-acl-domain-security (18 tests)
- [x] 16-custom-permission-evaluator (tests)
- [x] 21-spring-session-redis (12 tests)
- [x] 22-security-events-auditing (tests)
- [x] 23-rate-limiting-brute-force (tests)

### Wave 6 (Specialized): COMPLETE
- [x] 09-x509-certificate (13 tests)
- [x] 12-saml2-login (13 tests)
- [x] 24-websocket-security (9 tests)
- [x] 25-reactive-security (12 tests)
- [x] 26-multi-tenancy (23 tests)
- [x] 27-security-testing (65 tests)

### Additional Boot 4 / Security 7 Discoveries
- `saml2Login()` post-processor removed: use `.with(authentication(new Saml2Authentication(...)))`
- `spring-security-messaging` not in Boot BOM: add explicit version
- `@AutoConfigureWebTestClient` moved to `org.springframework.boot.webtestclient.autoconfigure`
- `HttpSecurity.authenticationManagerResolver()` removed: use `AuthenticationFilter` directly
- `@EnableRedisHttpSession` required explicitly (no auto-configuration in Boot 4)
- `permissionsPolicy()` returns `PermissionsPolicyConfig` not `HeadersConfigurer`: use block-style lambda
- HSTS only sent over HTTPS by default: use `AnyRequestMatcher` to test over HTTP
