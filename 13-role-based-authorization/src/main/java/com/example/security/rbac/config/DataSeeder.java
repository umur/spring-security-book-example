package com.example.security.rbac.config;

import com.example.security.rbac.model.AppUser;
import com.example.security.rbac.model.Project;
import com.example.security.rbac.repository.AppUserRepository;
import com.example.security.rbac.repository.ProjectRepository;
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
                               ProjectRepository projectRepo,
                               PasswordEncoder encoder) {
        return args -> {
            if (userRepo.count() == 0) {
                userRepo.save(new AppUser("user", encoder.encode("user"), "USER"));
                userRepo.save(new AppUser("manager", encoder.encode("manager"), "MANAGER"));
                userRepo.save(new AppUser("admin", encoder.encode("admin"), "ADMIN"));
            }
            if (projectRepo.count() == 0) {
                projectRepo.save(new Project("Alpha", "First project", "admin"));
                projectRepo.save(new Project("Beta", "Second project", "manager"));
            }
        };
    }
}
