package com.cinetrack.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * Chapter 13: In-memory user store.
 *
 * alice: regular user, maps to a PREMIUM subscriber in the CineTrack domain.
 * admin: operations user for internal tooling.
 *
 * {noop} prefix means no password encoding: fine for a book example,
 * not for production (use BCryptPasswordEncoder there).
 */
@Configuration
public class CineTrackUserDetailsService {

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails alice = User.withUsername("alice")
                .password("{noop}alice123")
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password("{noop}admin123")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(alice, admin);
    }
}
