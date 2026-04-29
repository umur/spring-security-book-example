package com.example.security.websocket.config;

import com.example.security.websocket.model.AppUser;
import com.example.security.websocket.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class DataSeeder {

    @Bean
    CommandLineRunner seedUsers(AppUserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (userRepository.count() == 0) {
                userRepository.save(AppUser.builder()
                        .username("admin")
                        .password(passwordEncoder.encode("admin"))
                        .role("ADMIN")
                        .enabled(true)
                        .build());
                userRepository.save(AppUser.builder()
                        .username("user")
                        .password(passwordEncoder.encode("user"))
                        .role("USER")
                        .enabled(true)
                        .build());
                log.info("Seeded users: admin (ADMIN), user (USER)");
            }
        };
    }
}
