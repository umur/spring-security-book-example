package com.cinetrack.security;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy;
import org.springframework.security.acls.domain.SpringCacheBasedAclCache;
import org.springframework.security.acls.jdbc.BasicLookupStrategy;
import org.springframework.security.acls.jdbc.JdbcMutableAclService;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.sql.DataSource;
import java.util.concurrent.TimeUnit;

/**
 * Wires the Spring Security ACL infrastructure.
 *
 * The chain of beans is:
 *   DataSource → LookupStrategy + AclCache → JdbcMutableAclService
 *             → AclPermissionEvaluator → MethodSecurityExpressionHandler
 *
 * {@code SpringCacheBasedAclCache} keeps recently-resolved ACL objects in
 * Caffeine so the database is not hit on every permission check.
 *
 * {@code AclAuthorizationStrategyImpl} decides who may administer ACLs
 * themselves (change ownership, update entries). Granting {@code ROLE_ADMIN}
 * that power is the sensible default for CineTrack.
 */
@Configuration
public class AclConfig {

    @Bean
    public AclCache aclCache(CacheManager cacheManager) {
        return new SpringCacheBasedAclCache(
                cacheManager.getCache("aclCache"),
                new DefaultPermissionGrantingStrategy(new ConsoleAuditLogger()),
                new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
    }

    @Bean
    public CacheManager cacheManager() {
        CaffeineCacheManager manager = new CaffeineCacheManager("aclCache");
        manager.setCaffeine(
                Caffeine.newBuilder()
                        .maximumSize(500)
                        .expireAfterWrite(10, TimeUnit.MINUTES)
        );
        return manager;
    }

    @Bean
    public LookupStrategy lookupStrategy(DataSource dataSource, AclCache aclCache) {
        return new BasicLookupStrategy(
                dataSource,
                aclCache,
                new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("ROLE_ADMIN")),
                new ConsoleAuditLogger()
        );
    }

    @Bean
    public MutableAclService aclService(DataSource dataSource, LookupStrategy lookupStrategy,
                                        AclCache aclCache) {
        JdbcMutableAclService service = new JdbcMutableAclService(dataSource, lookupStrategy, aclCache);
        // H2 2.x in MySQL compat mode supports LAST_INSERT_ID() for the identity query.
        service.setClassIdentityQuery("SELECT LAST_INSERT_ID()");
        service.setSidIdentityQuery("SELECT LAST_INSERT_ID()");
        return service;
    }

    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            MutableAclService aclService) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(new AclPermissionEvaluator(aclService));
        return handler;
    }
}
