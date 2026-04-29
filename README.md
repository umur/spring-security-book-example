# Spring Security Examples

A comprehensive, multi-module reference project covering every major Spring Security feature. Each module is a self-contained, runnable Spring Boot application with tests and documentation.

**Spring Boot 4.0.4** | **Spring Security 7.0.4** | **Java 21** | **Maven**

---

## Quick Start

```bash
# Build everything
mvn clean verify

# Run a specific module
mvn spring-boot:run -pl 01-form-login

# Test a specific module
mvn clean test -pl 03-jwt-authentication
```

Each module runs on its own port — you can run multiple simultaneously.

---

## Modules

### Authentication

| # | Module | Port | Description |
|---|--------|------|-------------|
| 01 | [Form Login](01-form-login) | 8081 | Custom login page, logout, success/failure handlers |
| 02 | [HTTP Basic](02-http-basic) | 8082 | Stateless REST API authentication |
| 03 | [JWT Authentication](03-jwt-authentication) | 8083 | Token issue/validate, refresh tokens, JJWT |
| 04 | [OAuth2 Login](04-oauth2-login) | 8084 | OAuth2/OIDC with external providers (Google, GitHub) |
| 05 | [OAuth2 Resource Server](05-oauth2-resource-server) | 8085 | JWT validation, scope-based authorization, JWK Set |
| 06 | [LDAP Authentication](06-ldap-authentication) | 8086 | LDAP directory auth with embedded UnboundID |
| 07 | [Custom Auth Provider](07-custom-authentication-provider) | 8087 | Custom AuthenticationProvider, multi-provider chain |
| 08 | [API Key Authentication](08-api-key-authentication) | 8088 | API key via custom filter, key generation/validation |
| 09 | [X.509 Certificate](09-x509-certificate) | 8089 | Mutual TLS, client certificate authentication |
| 10 | [Multi-Factor Auth](10-multi-factor-auth) | 8090 | TOTP-based 2FA (Google Authenticator compatible) |
| 11 | [Remember Me](11-remember-me) | 8091 | Persistent token-based remember-me login |
| 12 | [SAML2 Login](12-saml2-login) | 8092 | SAML 2.0 SSO with SP metadata endpoint |

### Authorization

| # | Module | Port | Description |
|---|--------|------|-------------|
| 13 | [Role-Based Authorization](13-role-based-authorization) | 8093 | RBAC, URL matchers, role hierarchy |
| 14 | [Method Security](14-method-security) | 8094 | @PreAuthorize, @PostAuthorize, @PreFilter, @PostFilter, SpEL |
| 15 | [ACL Domain Security](15-acl-domain-security) | 8095 | Object-level permissions with Spring Security ACL |
| 16 | [Custom Permission Evaluator](16-custom-permission-evaluator) | 8096 | Custom PermissionEvaluator with hasPermission() |

### Protection

| # | Module | Port | Description |
|---|--------|------|-------------|
| 17 | [CSRF Protection](17-csrf-protection) | 8097 | Token-based CSRF for forms and SPAs, BREACH protection |
| 18 | [CORS Configuration](18-cors-configuration) | 8098 | Fine-grained CORS rules, preflight handling |
| 19 | [Security Headers](19-security-headers) | 8099 | CSP, HSTS, X-Frame-Options, Permissions-Policy |

### Session Management

| # | Module | Port | Description |
|---|--------|------|-------------|
| 20 | [Session Management](20-session-management) | 8100 | Policies, concurrent sessions, fixation protection |
| 21 | [Spring Session + Redis](21-spring-session-redis) | 8101 | Distributed sessions with Redis |

### Advanced

| # | Module | Port | Description |
|---|--------|------|-------------|
| 22 | [Security Events & Auditing](22-security-events-auditing) | 8102 | Authentication/authorization event listeners, audit trail |
| 23 | [Rate Limiting & Brute Force](23-rate-limiting-brute-force) | 8103 | Login attempt tracking, account lockout |
| 24 | [WebSocket Security](24-websocket-security) | 8104 | STOMP authentication, message-level authorization |
| 25 | [Reactive Security](25-reactive-security) | 8105 | WebFlux, ReactiveUserDetailsService, R2DBC |
| 26 | [Multi-Tenancy](26-multi-tenancy) | 8106 | Tenant-aware auth, per-tenant AuthenticationManager |
| 27 | [Security Testing](27-security-testing) | 8107 | Comprehensive testing patterns and techniques |
| 28 | [Password Encoding](28-password-encoding) | 8108 | BCrypt, Argon2, DelegatingPasswordEncoder, migration |
| 29 | [Custom Filter Chain](29-custom-filter-chain) | 8109 | Multiple SecurityFilterChain beans, custom filters |
| 30 | [Microservice Security](30-microservice-security) | 8110 | Service-to-service OAuth2 client credentials |

---

## Architecture

- **Thin controllers** — controllers only accept requests and delegate to service layer
- **All business logic in services** — testable independently from HTTP layer
- **Java records** for DTOs, **Lombok** for entities
- **SecurityFilterChain as @Bean** with lambda DSL (Spring Security 7 style)
- **No deprecated APIs** — no WebSecurityConfigurerAdapter, no .and() chaining

## Testing

Every module includes two test layers:

- **Unit tests** (`*Test.java`) — `@SpringBootTest` + `@AutoConfigureMockMvc`, security post-processors
- **Integration tests** (`*IntegrationTest.java`) — `@SpringBootTest(RANDOM_PORT)` with Testcontainers (PostgreSQL, Redis), no mocking

```bash
# Run all tests
mvn clean test

# Run a single module's tests
mvn test -pl 14-method-security
```

## Prerequisites

- **Java 21+**
- **Maven 3.8+**
- **Docker** (for Testcontainers in integration tests)

## Default Credentials

Most modules seed test users via `ApplicationRunner`:

| Username | Password | Role |
|----------|----------|------|
| admin | admin | ADMIN |
| user | user | USER |

Check each module's configuration for specific credentials.

---

More from the author at [umurinan.com](https://umurinan.com).
