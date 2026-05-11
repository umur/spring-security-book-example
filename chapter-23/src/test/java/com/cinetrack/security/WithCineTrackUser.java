package com.cinetrack.security;

import org.springframework.security.test.context.support.WithSecurityContext;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Populates the security context with a {@link CineTrackPrincipal} as the principal.
 *
 * The factory builds a UsernamePasswordAuthenticationToken so any controller
 * injecting {@code @AuthenticationPrincipal CineTrackPrincipal} receives the
 * configured instance — no JWT or HTTP session required.
 *
 * Usage:
 * <pre>
 * {@literal @}Test
 * {@literal @}WithCineTrackUser(userId = "u99", email = "charlie@cinetrack.io", tier = "PREMIUM")
 * void premiumUserSeesExtraContent() { ... }
 * </pre>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@WithSecurityContext(factory = WithCineTrackUserSecurityContextFactory.class)
public @interface WithCineTrackUser {

    String userId() default "u1";

    String email() default "test@cinetrack.io";

    String tier() default "FREE";
}
