package com.example.security.custompermission.config;

import com.example.security.custompermission.security.ProjectPermissionEvaluator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * Registers the custom {@link ProjectPermissionEvaluator} with the method security
 * expression handler so that {@code hasPermission()} in {@code @PreAuthorize} /
 * {@code @PostAuthorize} delegates to our business-rule evaluator.
 */
@Configuration
@EnableMethodSecurity
public class MethodSecurityConfig {

    @Bean
    MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            ProjectPermissionEvaluator permissionEvaluator) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(permissionEvaluator);
        return handler;
    }
}
