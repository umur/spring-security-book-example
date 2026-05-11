# Spring Security 7: From Internals to Production

> Security code you can reason about under pressure — because at 2am during a pentest is not the time to read the docs.

Companion code for the book **Spring Security 7: From Internals to Production** by [Umur Inan](https://umurinan.com).

## About the book

Most Spring Security documentation tells you what to configure. This book tells you what actually happens. The filter chain, the security context, authentication and authorization architecture, tokens, sessions, MFA, passkeys, OAuth2 (client + resource server + your own authorization server), SAML2, method-level authorization, reactive security, multi-tenancy, zero-trust microservices — every concept implemented against the same CinéTrack streaming platform and stress-tested.

## Quick start

```bash
git clone https://github.com/umur/spring-security-book-example
cd spring-security-book-example/chapter-01
mvn spring-boot:run
```

## Layout

One standalone Spring Boot project per chapter, in the `com.cinetrack.*` package namespace:

- `chapter-01/` — Filter chain, SecurityContext, AuthenticationEntryPoint
- `chapter-02/ … chapter-24/` — cumulative CinéTrack security architecture, each chapter adding a layer

Each chapter directory is a complete, runnable application; later chapters build on the previous ones.

## Stack

- Java 21 (LTS)
- Spring Boot 4
- Spring Security 7
- jjwt 0.12.x
- PostgreSQL 16
- Testcontainers for integration tests

## About the author

I'm Umur Inan. I write books about Spring Boot, Java, distributed systems, and the practices that make production reliable.

📚 **More writing and books → [umurinan.com](https://umurinan.com)**

## License

MIT — see [LICENSE](LICENSE).
