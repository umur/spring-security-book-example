package com.example.security.rememberme.config;

import com.example.security.rememberme.model.AppUser;
import com.example.security.rememberme.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class DataSeeder {

    @Bean
    ApplicationRunner seedUsers(AppUserRepository repo, PasswordEncoder encoder) {
        return args -> {
            if (repo.count() == 0) {
                repo.save(new AppUser("admin", encoder.encode("admin"), "ADMIN"));
                repo.save(new AppUser("user", encoder.encode("user"), "USER"));
            }
        };
    }
}
