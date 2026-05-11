# Spring Security 7 — From Internals to Production

Companion code for the book *Spring Security 7: From Internals to Production* by Umur Inan.

## Layout

One Spring Boot project per book chapter. Each `chapter-NN/` directory is the cumulative state of the CinéTrack streaming platform at the end of that chapter:

- chapter-01 — Filter chain, SecurityContext, AuthenticationEntryPoint
- chapter-02..24 — Each subsequent chapter builds on the previous; the security architecture grows as the reader progresses

## Run

```bash
cd chapter-NN
mvn spring-boot:run
```

Each chapter is a standalone Spring Boot 4 application targeting Spring Security 7. The domain is CinéTrack, a streaming platform with services for catalog, users, recommendations, subscriptions, and reviews. See the book for the per-chapter requirements and the security features added at each step.
