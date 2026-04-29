package com.example.security.custompermission.config;

import com.example.security.custompermission.model.AppUser;
import com.example.security.custompermission.repository.AppUserRepository;
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
                userRepo.save(new AppUser("alice",   encoder.encode("alice")));
                userRepo.save(new AppUser("bob",     encoder.encode("bob")));
                userRepo.save(new AppUser("charlie", encoder.encode("charlie")));
                userRepo.save(new AppUser("diana",   encoder.encode("diana")));
            }
        };
    }
}
