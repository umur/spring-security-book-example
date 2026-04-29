package com.example.security.multitenancy.config;

import com.example.security.multitenancy.model.TenantUser;
import com.example.security.multitenancy.model.TenantData;
import com.example.security.multitenancy.repository.TenantUserRepository;
import com.example.security.multitenancy.repository.TenantDataRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Seeds demo users and data for both tenants on startup.
 *
 * Tenant A: admin/admin (ADMIN), user/user (USER)
 * Tenant B: admin/admin (ADMIN), bob/bob (USER)
 *
 * Note: "admin" in tenant-a and "admin" in tenant-b are independent identities.
 */
@Configuration
@RequiredArgsConstructor
public class DataSeeder {

    @Bean
    ApplicationRunner seedTenantData(TenantUserRepository userRepo,
                                     TenantDataRepository dataRepo,
                                     PasswordEncoder encoder) {
        return args -> {
            if (userRepo.count() == 0) {
                // Tenant A users
                userRepo.save(new TenantUser("tenant-a", "admin", encoder.encode("admin"), "ADMIN"));
                userRepo.save(new TenantUser("tenant-a", "user", encoder.encode("user"), "USER"));

                // Tenant B users — "admin" username reused but completely separate identity
                userRepo.save(new TenantUser("tenant-b", "admin", encoder.encode("admin"), "ADMIN"));
                userRepo.save(new TenantUser("tenant-b", "bob", encoder.encode("bob"), "USER"));
            }
            if (dataRepo.count() == 0) {
                dataRepo.save(new TenantData("tenant-a", "Tenant A - Record 1"));
                dataRepo.save(new TenantData("tenant-a", "Tenant A - Record 2"));
                dataRepo.save(new TenantData("tenant-b", "Tenant B - Record 1"));
                dataRepo.save(new TenantData("tenant-b", "Tenant B - Record 2"));
            }
        };
    }
}
