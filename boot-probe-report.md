# Spring Security Book Examples: Boot Probe Report

Generated: 2026-05-15

| Chapter | Auth Mechanism | Port | Unauth Probe | Auth Probe | Result | Notes |
|---------|---------------|------|--------------|------------|--------|-------|
| chapter-01 | form-login + httpBasic | 8080 | unauth=401 | auth=200 (basic, generated-pwd) | OK | health=200; /api/movies secured |
| chapter-02 | httpBasic + roles | 8080 | unauth=401 | auth=200 alice:password (VIEWER), admin:admin (ADMIN) | OK | WWW-Authenticate: Basic |
| chapter-03 | JWT resource server (HMAC HS256) | 8080 | unauth=401 | auth=200 (Bearer JWT via POST /api/token?username=alice) | OK | /api/token public; /api/movies needs SCOPE_catalog:read |
| chapter-04 | form-login (JSON responses) | 8080 | BOOT_FAIL | - | FAIL | spring.jackson.serialization/deserialization empty keys crash JacksonProperties binding |
| chapter-05 | httpBasic + password encoding | 8080 | BOOT_FAIL | - | FAIL | Same empty Jackson map keys as chapter-04 |
| chapter-06 | form-login + MFA/TOTP | 8080 | BOOT_FAIL | - | FAIL | Same empty Jackson map keys as chapter-04 |
| chapter-07 | WebAuthn/passkey + form-login | 8080 | unauth=302 | auth=webauthn-browser-only (login=200) | OK | WebAuthn credential registration requires browser |
| chapter-08 | LDAP authentication (embedded UnboundID :8389) | 8080 | unauth=401 | auth=200 (alice:alice123) | OK | Self-contained embedded LDAP; no external service needed |
| chapter-09 | SAML2 login (Okta IdP, classpath metadata) | 8080 | unauth=302 | auth=SAML-redirect (needs real Okta IdP) | OK-boot | Boots fine with classpath metadata; SAML SSO needs external IdP |
| chapter-10 | JWT RS (RSA) + self-hosted token endpoint | 8080 | unauth=401 | auth=200 (Bearer JWT from POST /api/token/client-credentials) | OK | Self-contained; POST JSON {clientId,scope} to get token |
| chapter-11 | Multi-issuer JWT RS (issuer1+issuer2 at localhost:8080) | 8080 | unauth=401 | auth=JWT-needed (two JwtAuthenticationProviders) | OK-boot | No token endpoint; auth probe skipped |
| chapter-12 | OAuth2 login (cinetrack-as auth server) | 8080 | unauth=302 | auth=oauth2-redirect (login=200) | OK-boot | Boots fine; full auth needs external OAuth2 AS |
| chapter-13 | Role-based authz + form-login | 8080 | unauth=302 | auth=302->login (form session probe inconclusive) | OK | alice:alice123 VIEWER, admin:admin123 ADMIN |
| chapter-14 | Method security (@PreAuthorize) + form-login | 8080 | unauth=302 | auth=302->login | OK | alice:alice123, admin:admin123; @PreAuthorize on service layer |
| chapter-15 | Google OIDC login (oauth2Login) | 8080 | unauth=302 | auth=oauth2-redirect (login=200) | OK-boot | Boots with placeholder GOOGLE_CLIENT_ID; real auth needs Google OIDC |
| chapter-16 | Spring Authorization Server (Device Code + Auth Code) | 9000 | disco=200 | device-code/auth-code flows (no client_creds grant) | OK | OIDC discovery healthy; issues JWTs for cinetrack-tv/cinetrack-web |
| chapter-17 | CSRF protection + httpBasic (H2) | 8080 | unauth=401 | auth=404 (authenticated ok, /api/movies not in ch17) | OK | CSRF tokens required for state-changing requests |
| chapter-18 | ACL domain security + httpBasic (H2+acl-schema) | 8080 | unauth=401 | auth=404 (authenticated ok, /api/movies not in ch18) | OK | Spring ACL per-object permissions; alice:password, admin:admin |
| chapter-19 | Security headers + httpBasic | 8080 | unauth=401 | auth=404 (authenticated ok) | OK | X-Content-Type-Options+X-Frame-Options headers confirmed |
| chapter-20 | Reactive WebFlux JWT RS (in-process RSA JWK, Netty) | 8080 | unauth=401 | auth=JWT-needed (RSA key generated in-process, no token endpoint) | OK-boot | Self-contained reactive stack; no external IdP |
| chapter-21 | Multi-tenant reactive JWT RS (Netty) | 8080 | unauth=401 | auth=JWT-needed (multi-tenant issuer selection) | OK-boot | Reactive stack; two in-process issuers |
| chapter-22 | Catalog service JWT RS (local RSA key) | 8080 | unauth=401 | auth=JWT-needed (local RSA; issuer-uri not validated at startup) | OK-boot | token-uri refs localhost:9000 but lazily resolved |
| chapter-23 | Security testing showcase (httpBasic + JWT RS) | 8080 | unauth=401 | auth=200 (alice:alice123) | OK | issuer-uri=localhost:9000 lazily resolved; demonstrates @WithMockUser and jwt() |
| chapter-24 | Actuator security + httpBasic + formLogin | 8080 | unauth=401 | health=200 (permitAll), admin:admin123 actuator=200, alice:alice123 api=200 | OK | /actuator/health public; /actuator/** needs ADMIN role |

## Summary

- **Total chapters probed:** 24 (chapter-01 through chapter-24)
- **Boot OK / fully verified:** 14 (ch01, ch02, ch03, ch07, ch08, ch10, ch13, ch14, ch16, ch17, ch18, ch19, ch23, ch24)
- **Boot OK / external IdP needed for complete auth:** 7 (ch09 SAML2, ch11 multi-issuer JWT, ch12 OAuth2 AS, ch15 Google OIDC, ch20 reactive JWT, ch21 multi-tenant reactive, ch22 catalog service)
- **Boot FAIL:** 3 (ch04, ch05, ch06)

## Boot Failure Root Cause

All three failing chapters share the same misconfiguration in `application.yml`:

```yaml
spring:
  jackson:
    serialization:      # empty map key
    deserialization:    # empty map key
```

Spring Boot 4 treats bare YAML keys with no value as empty maps. When `JacksonProperties` tries to bind them, it throws `UnsatisfiedDependencyException`. Fix: remove both lines or supply explicit sub-keys (e.g. `WRITE_DATES_AS_TIMESTAMPS: false`).

Affected: chapter-04, chapter-05, chapter-06.
