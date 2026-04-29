package com.example.security.testing.config;

import com.example.security.testing.model.AppUser;
import com.example.security.testing.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Seeds the in-memory H2 database with two users on startup:
 *
 *   user  / user   — ROLE_USER
 *   admin / admin  — ROLE_ADMIN
 *
 * These credentials are used by TestRestTemplate integration tests that
 * perform real HTTP Basic or form-login authentication against a running
 * server, and by HTTP Basic MockMvc tests via .with(httpBasic(...)).
 */
@Component
@RequiredArgsConstructor
public class DataSeeder implements ApplicationRunner {

    private final AppUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(ApplicationArguments args) {
        if (userRepository.count() == 0) {
            userRepository.save(new AppUser("user",
                    passwordEncoder.encode("user"), "USER"));
            userRepository.save(new AppUser("admin",
                    passwordEncoder.encode("admin"), "ADMIN"));
        }
    }
}
