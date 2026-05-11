package com.cinetrack;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldif.LDIFReader;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.InputStream;

/**
 * Stands up an embedded UnboundID LDAP server on port 8389.
 *
 * <p>UnboundID replaces the older ApacheDS / LDAP SDK dependency that
 * Spring Security used before version 7. It is lighter, thread-safe, and
 * does not require external process management.
 *
 * <p>The server is seeded from {@code ldap-test-server.ldif}, which contains
 * the {@code dc=cinetrack,dc=io} tree, two users (alice, bob) and two groups
 * (viewers, admins).
 */
@Configuration
public class EmbeddedLdapConfig {

    @Bean(destroyMethod = "shutDown")
    public InMemoryDirectoryServer embeddedLdapServer() throws Exception {
        InMemoryDirectoryServerConfig config =
                new InMemoryDirectoryServerConfig("dc=cinetrack,dc=io");

        config.addAdditionalBindCredentials("cn=admin,dc=cinetrack,dc=io", "secret");

        config.setListenerConfigs(
                InMemoryListenerConfig.createLDAPConfig("default", 8389)
        );

        InMemoryDirectoryServer server = new InMemoryDirectoryServer(config);

        try (InputStream ldif = new ClassPathResource("ldap-test-server.ldif").getInputStream()) {
            server.importFromLDIF(false, new LDIFReader(ldif));
        }

        server.startListening();
        return server;
    }
}
