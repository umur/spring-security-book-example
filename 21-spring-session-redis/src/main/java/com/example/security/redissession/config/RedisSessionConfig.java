package com.example.security.redissession.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

/**
 * Activates Spring Session with Redis-backed HttpSession storage.
 *
 * Spring Session 4 / Spring Boot 4 removed auto-configuration for Spring Session,
 * so @EnableRedisHttpSession must be declared explicitly. The namespace matches
 * the key prefix used in application.yml and asserted in integration tests.
 *
 * FlushMode defaults to ON_SAVE (write on session commit). Integration tests
 * override it to IMMEDIATE via a SessionRepositoryCustomizer bean so that
 * Redis key assertions work within the same request.
 */
@Configuration
@EnableRedisHttpSession(
        redisNamespace = "spring:session:redis-example",
        maxInactiveIntervalInSeconds = 1800
)
public class RedisSessionConfig {
}
