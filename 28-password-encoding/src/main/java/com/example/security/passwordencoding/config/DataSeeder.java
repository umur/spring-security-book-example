package com.example.security.passwordencoding.config;

import com.example.security.passwordencoding.model.AppUser;
import com.example.security.passwordencoding.repository.AppUserRepository;
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
                // admin is encoded with the primary DelegatingPasswordEncoder (bcrypt by default)
                repo.save(new AppUser("admin", encoder.encode("admin123"), "ADMIN"));
                repo.save(new AppUser("user", encoder.encode("user123"), "USER"));
            }
        };
    }
}
