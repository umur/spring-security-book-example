# Spring Security 7: From Internals to Production

> Security code you can reason about under pressure. 2am during a pentest is not the time to read the docs.

![Java](https://img.shields.io/badge/Java-21-ED8B00?logo=openjdk&logoColor=white) ![Spring Boot](https://img.shields.io/badge/Spring_Boot-4.0-6DB33F?logo=spring&logoColor=white) ![Spring Security](https://img.shields.io/badge/Spring_Security-7-6DB33F?logo=springsecurity&logoColor=white) ![License: MIT](https://img.shields.io/badge/License%3A_MIT-MIT-blue)

Companion code for **Spring Security 7: From Internals to Production** by [Umur Inan](https://umurinan.com).

## About the book

Most Spring Security documentation tells you what to configure. This book tells you what actually happens. The filter chain, the security context, authentication and authorization architecture, tokens, sessions, MFA, passkeys, OAuth2 (client plus resource server plus your own authorization server), SAML2, method-level authorization, reactive security, multi-tenancy, zero-trust microservices. Every concept implemented against the same **CinéTrack** streaming platform and stress-tested.

## Who this is for

- Spring Boot engineers who configure security by copying Stack Overflow answers
- Developers building their first OAuth2 integration or custom authorization server
- Security-conscious engineers who need to understand what the framework does under load and under attack

## Prerequisites

- Java 21 LTS ([Temurin](https://adoptium.net))
- Maven 3.9+ (or use the bundled `./mvnw` wrapper)
- Docker and Docker Compose (PostgreSQL 16, Redis for session chapters)

## Quick start

```bash
git clone https://github.com/umur/spring-security-book-example
cd spring-security-book-example/chapter-01
mvn spring-boot:run
```

## Chapters

Each `chapter-NN/` directory is a self-contained, runnable Spring Boot project in the `com.cinetrack.*` package namespace. Later chapters build on the previous ones. Each chapter directory has its own `README.md` with the delta and run instructions.

- `chapter-01`: Spring Security 7 internals. Filter chain, SecurityContext, authentication model, the new DSL, exception translation
- `chapter-02`: CinéTrack's security blueprint. Threat model, authentication strategy, authorization domains, token strategy
- `chapter-03`: JWT and token mastery. Anatomy, signing algorithms, JWK sets, key rotation, opaque tokens, DPoP
- `chapter-04`: session management and CSRF. Creation policies, Spring Session storage, fixation, concurrency, CORS
- `chapter-05`: HTTP hardening. Security headers, CSP, HTTP firewall, password encoding, the crypto module
- `chapter-06`: multi-factor authentication. The factor authority pattern, TOTP, custom factors, factor-aware authorization
- `chapter-07`: passwordless. WebAuthn protocol, credential repositories, registration and authentication ceremonies, passkeys
- `chapter-08`: enterprise auth. LDAP, X.509, Kerberos and SPNEGO, pre-authentication
- `chapter-09`: SAML 2.0. SP, IdP, assertions, bindings, single logout, certificate rotation
- `chapter-10`: OAuth2 and OIDC protocol internals. Threat model, grant types, PKCE, token types, DPoP
- `chapter-11`: resource server. JWT validation pipeline, multi-tenant, claim-to-authority mapping, opaque token validation
- `chapter-12`: OAuth2 client. Client registration, authorization code with PKCE, AuthorizedClientManager, token relay
- `chapter-13`: building CinéTrack's own IdP. Authorization Server setup, client registration, user authentication and consent
- `chapter-14`: customizing tokens and claims. OAuth2TokenCustomizer, token exchange, introspection, refresh token policy
- `chapter-15`: OIDC, social login, dynamic client registration. ID Token, UserInfo, federation
- `chapter-16`: advanced Authorization Server flows. Device grant, custom grants, token exchange, pushed authorization requests
- `chapter-17`: method security and SpEL. `@PreAuthorize`, `@PostAuthorize`, `@PreFilter`, `@PostFilter`, custom expressions, role hierarchies
- `chapter-18`: domain object security. ACL concepts, JDBC-backed ACL, PermissionEvaluator, caching, inheritance
- `chapter-19`: policy-based authorization. AuthorizationManager, PathPatternRequestMatcher, OPA integration, authorization events
- `chapter-20`: WebFlux security. `@EnableWebFluxSecurity`, SecurityWebFilterChain, ReactiveSecurityContextHolder, reactive method security
- `chapter-21`: reactive OAuth2. Resource server, ReactiveJwtDecoder, reactive opaque token, reactive AuthorizedClientManager
- `chapter-22`: zero-trust microservices. Service identity, token relay patterns, mTLS, Spring Cloud Gateway, context propagation
- `chapter-23`: testing Spring Security. `spring-security-test`, MockMvc support, `@WithMockUser`, OAuth2 testing, WireMock, Testcontainers
- `chapter-24`: observability, audit logging, secrets. Auth events, Micrometer, distributed tracing, structured logging, Vault

## Stack

- Java 21 LTS
- Spring Boot 4.0.6
- Spring Security 7
- jjwt 0.12.x
- PostgreSQL 16
- Redis 7 (session and cache chapters)
- Testcontainers for integration tests

## Related books

- [Spring Boot 4 in Practice](https://github.com/umur/spring-boot-example): introduces Spring Security in chapter 9. This book picks up where that ends.
- [Microservices with Spring Boot 4](https://github.com/umur/microservices-example): service-to-service security, JWT propagation, and zero-trust covered in both books from different angles.
- [OAuth2 Survival Guide](https://github.com/umur/oauth-survival-guide-example): the field-guide companion to chapters 10 through 16.

## About the author

I'm Umur Inan, a Principal Software Engineer with 15 years of experience building backend systems across enterprise, government, and high-growth environments. I specialize in microservices architecture, distributed systems, and cloud-native development, with deep expertise in Spring Boot, Kafka, and Kubernetes. Based in New York City, I've shipped products across five countries and hold a Master's in Computer Science and a Bachelor's in Computer Engineering.

[umurinan.com](https://umurinan.com)

## License

MIT. See [LICENSE](LICENSE).
