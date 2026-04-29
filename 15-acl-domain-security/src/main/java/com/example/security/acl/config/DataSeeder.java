package com.example.security.acl.config;

import com.example.security.acl.model.AppUser;
import com.example.security.acl.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class DataSeeder {

    @Bean
    ApplicationRunner seedUsers(AppUserRepository userRepo, PasswordEncoder encoder) {
        return args -> {
            if (userRepo.count() == 0) {
                userRepo.save(new AppUser("admin", encoder.encode("admin"), "ADMIN"));
                userRepo.save(new AppUser("alice", encoder.encode("alice"), "USER"));
                userRepo.save(new AppUser("bob",   encoder.encode("bob"),   "USER"));
                userRepo.save(new AppUser("charlie", encoder.encode("charlie"), "USER"));
            }
        };
    }
}
