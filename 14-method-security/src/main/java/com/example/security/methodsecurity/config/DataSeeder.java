package com.example.security.methodsecurity.config;

import com.example.security.methodsecurity.model.AppUser;
import com.example.security.methodsecurity.model.Document;
import com.example.security.methodsecurity.repository.AppUserRepository;
import com.example.security.methodsecurity.repository.DocumentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class DataSeeder {

    @Bean
    ApplicationRunner seedData(AppUserRepository userRepo,
                               DocumentRepository documentRepo,
                               PasswordEncoder encoder) {
        return args -> {
            if (userRepo.count() == 0) {
                userRepo.save(new AppUser("admin", encoder.encode("admin"), "ADMIN"));
                userRepo.save(new AppUser("alice", encoder.encode("alice"), "USER"));
                userRepo.save(new AppUser("bob", encoder.encode("bob"), "USER"));
            }
            if (documentRepo.count() == 0) {
                documentRepo.save(new Document("Alice's Report", "Quarterly results", "alice"));
                documentRepo.save(new Document("Bob's Notes", "Meeting notes", "bob"));
                documentRepo.save(new Document("Admin Policy", "Company policy document", "admin"));
            }
        };
    }
}
