package com.example.security.ldap.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.ldap.server.UnboundIdContainer;

/**
 * Configures the embedded UnboundID LDAP server and the LDAP context source.
 *
 * UnboundIdContainer implements ApplicationContextAware + InitializingBean.
 * Declaring it as a @Bean lets the Spring container call setApplicationContext
 * before afterPropertiesSet, enabling classpath LDIF resource loading.
 *
 * Port 0 = ephemeral: the OS assigns a free port. container.getPort() returns
 * the real port only after afterPropertiesSet() has completed, so the
 * contextSource bean (which depends on ldapContainer) always sees the real port.
 */
@Configuration
public class LdapServerConfig {

    @Bean
    UnboundIdContainer ldapContainer() {
        var container = new UnboundIdContainer("dc=example,dc=com", "classpath:users.ldif");
        container.setPort(0);
        return container;
    }

    @Bean
    BaseLdapPathContextSource contextSource(UnboundIdContainer container) {
        int ldapPort = container.getPort();
        var ctx = new LdapContextSource();
        ctx.setUrl("ldap://localhost:" + ldapPort);
        ctx.setBase("dc=example,dc=com");
        ctx.afterPropertiesSet();
        return ctx;
    }
}
