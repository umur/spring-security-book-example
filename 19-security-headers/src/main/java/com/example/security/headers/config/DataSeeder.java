package com.example.security.headers.config;

import com.example.security.headers.model.AppUser;
import com.example.security.headers.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class DataSeeder {

    @Bean
    ApplicationRunner seedData(AppUserRepository userRepo, PasswordEncoder encoder) {
        return args -> {
            if (userRepo.count() == 0) {
                userRepo.save(new AppUser("admin", encoder.encode("admin"), "ADMIN"));
                userRepo.save(new AppUser("alice", encoder.encode("alice"), "USER"));
            }
        };
    }
}
