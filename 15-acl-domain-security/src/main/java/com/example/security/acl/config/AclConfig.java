package com.example.security.acl.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.acls.AclPermissionCacheOptimizer;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.domain.*;
import org.springframework.security.acls.jdbc.BasicLookupStrategy;
import org.springframework.security.acls.jdbc.JdbcMutableAclService;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.PermissionGrantingStrategy;

import javax.sql.DataSource;

/**
 * Configures Spring Security ACL: the ACL service, lookup strategy, cache, and
 * wires the AclPermissionEvaluator into the method security expression handler.
 */
@Configuration
@EnableCaching
public class AclConfig {

    // -----------------------------------------------------------------------
    // JCache / EhCache setup
    // -----------------------------------------------------------------------

    @Bean
    CacheManager cacheManager() {
        // ConcurrentMapCacheManager is per-Spring-context (not a JVM singleton like
        // EhCache's JCachingProvider), which prevents ACL cache pollution between
        // the H2 MockMvc context and the PostgreSQL Testcontainers context.
        return new ConcurrentMapCacheManager("aclCache");
    }

    // -----------------------------------------------------------------------
    // ACL infrastructure beans
    // -----------------------------------------------------------------------

    @Bean
    AclAuthorizationStrategy aclAuthorizationStrategy() {
        // Only ROLE_ADMIN may change ACL ownership / auditing / entries
        return new AclAuthorizationStrategyImpl(
                new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    @Bean
    PermissionGrantingStrategy permissionGrantingStrategy() {
        return new DefaultPermissionGrantingStrategy(new ConsoleAuditLogger());
    }

    @Bean
    AclCache aclCache(CacheManager cacheManager,
                      PermissionGrantingStrategy permissionGrantingStrategy,
                      AclAuthorizationStrategy aclAuthorizationStrategy) {
        return new SpringCacheBasedAclCache(
                cacheManager.getCache("aclCache"),
                permissionGrantingStrategy,
                aclAuthorizationStrategy);
    }

    @Bean
    LookupStrategy lookupStrategy(DataSource dataSource,
                                   AclCache aclCache,
                                   AclAuthorizationStrategy aclAuthorizationStrategy,
                                   PermissionGrantingStrategy permissionGrantingStrategy) {
        return new BasicLookupStrategy(
                dataSource,
                aclCache,
                aclAuthorizationStrategy,
                permissionGrantingStrategy);
    }

    @Bean
    MutableAclService aclService(DataSource dataSource,
                                  LookupStrategy lookupStrategy,
                                  AclCache aclCache,
                                  @Value("${acl.class-identity-query:SELECT CURRENT VALUE FOR acl_class_sequence}") String classIdentityQuery,
                                  @Value("${acl.sid-identity-query:SELECT CURRENT VALUE FOR acl_sid_sequence}") String sidIdentityQuery) {
        JdbcMutableAclService service = new JdbcMutableAclService(dataSource, lookupStrategy, aclCache);
        service.setClassIdentityQuery(classIdentityQuery);
        service.setSidIdentityQuery(sidIdentityQuery);
        return service;
    }

    // -----------------------------------------------------------------------
    // Wire ACL evaluator into method security
    // -----------------------------------------------------------------------

    @Bean
    AclPermissionEvaluator aclPermissionEvaluator(MutableAclService aclService) {
        return new AclPermissionEvaluator(aclService);
    }

    @Bean
    MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            AclPermissionEvaluator aclPermissionEvaluator,
            MutableAclService aclService) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(aclPermissionEvaluator);
        handler.setPermissionCacheOptimizer(new AclPermissionCacheOptimizer(aclService));
        return handler;
    }
}
