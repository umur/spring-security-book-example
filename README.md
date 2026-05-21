# Spring Security 7: From Internals to Production

> Security code you can reason about under pressure: because at 2am during a pentest is not the time to read the docs.

![Java](https://img.shields.io/badge/Java-21-ED8B00?logo=openjdk&logoColor=white) ![Spring Boot](https://img.shields.io/badge/Spring_Boot-4.0-6DB33F?logo=spring&logoColor=white) ![Spring Security](https://img.shields.io/badge/Spring_Security-7-6DB33F?logo=springsecurity&logoColor=white) ![License: MIT](https://img.shields.io/badge/License%3A_MIT-MIT-blue)

Companion code for **Spring Security 7: From Internals to Production** by [Umur Inan](https://umurinan.com).

## About the book

Most Spring Security documentation tells you what to configure. This book tells you what actually happens. The filter chain, the security context, authentication and authorization architecture, tokens, sessions, MFA, passkeys, OAuth2 (client + resource server + your own authorization server), SAML2, method-level authorization, reactive security, multi-tenancy, zero-trust microservices. Every concept implemented against the same CinéTrack streaming platform and stress-tested.

## Who this is for

- Spring Boot engineers who configure security by copying Stack Overflow answers
- Developers building their first OAuth2 integration or custom authorization server
- Security-conscious engineers who need to understand what the framework actually does under load and under attack

## Chapters

1. Spring Security 7 Internals
2. CineTrack's Security Blueprint
3. JWT and Token Mastery
4. Session Management and CSRF
5. HTTP Hardening: Headers, Firewall, and Crypto
6. Multi-Factor Authentication
7. Passwordless Authentication: WebAuthn and Passkeys
8. Enterprise Authentication: LDAP, X.509, and Kerberos
9. SAML 2.0
10. OAuth2 and OIDC Protocol Internals
11. Resource Server: Protecting CineTrack's APIs
12. OAuth2 Client: CineTrack as a Consumer
13. Building CineTrack's Own IdP from Scratch
14. Customizing Tokens and Claims
15. OIDC, Social Login, and Dynamic Client Registration
16. Advanced Authorization Server Flows
17. Method Security and SpEL
18. Domain Object Security: ACL
19. Policy-Based Authorization and Authorization Events
20. WebFlux Security: The Reactive Model
21. Reactive OAuth2: Resource Server, Client, and Authorization Server
22. Zero-Trust Microservices
23. Testing Spring Security
24. Observability, Audit Logging, and Secrets

## Prerequisites

- Java 21 LTS ([Temurin](https://adoptium.net))
- Maven 3.9+
- Docker & Docker Compose (PostgreSQL 16)

## Quick start

```bash
git clone https://github.com/umur/spring-security-book-example
cd spring-security-book-example/chapter-01
mvn spring-boot:run
```

## Layout

One standalone Spring Boot project per chapter, in the `com.cinetrack.*` package namespace:

- `chapter-01/`: Filter chain, SecurityContext, AuthenticationEntryPoint
- `chapter-02/ ... chapter-24/`: cumulative CinéTrack security architecture, each chapter adding a layer

Each chapter directory is a complete, runnable application; later chapters build on the previous ones.

## Stack

- Java 21 (LTS)
- Spring Boot 4
- Spring Security 7
- jjwt 0.12.x
- PostgreSQL 16
- Testcontainers for integration tests

## Related books

- [Spring Boot 4 in Practice](https://github.com/umur/spring-boot-example): introduces Spring Security in Chapter 9; this book covers everything beyond that
- [Microservices with Spring Boot 4](https://github.com/umur/microservices-example): service-to-service security, JWT propagation, and zero-trust covered in both books from different angles
- [Cloud-Native Spring Boot on Kubernetes](https://github.com/umur/kubernetes-example): Workload Identity and supply-chain provenance extend the security model to the cluster level

## About the author

I'm Umur Inan. I write production-focused books about Java, Spring Boot, distributed systems, and everything that makes software reliable at scale.

[umurinan.com](https://umurinan.com)

## License

MIT. See [LICENSE](LICENSE).
