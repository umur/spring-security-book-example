package com.cinetrack.security;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.SpringAuthorizationEventPublisher;

/**
 * Activates Spring Security authorization event publishing.
 *
 * Without this bean, Spring Security evaluates authorization decisions silently.
 * With it, every denial fires an {@code AuthorizationDeniedEvent} into the
 * application context so {@link SecurityAuditListener} (and any other listeners)
 * can react: without coupling the filter chain code to audit logic.
 */
@Configuration
public class AuthorizationEventPublisherConfig {

    @Bean
    public SpringAuthorizationEventPublisher authorizationEventPublisher(
            ApplicationEventPublisher applicationEventPublisher
    ) {
        return new SpringAuthorizationEventPublisher(applicationEventPublisher);
    }
}
