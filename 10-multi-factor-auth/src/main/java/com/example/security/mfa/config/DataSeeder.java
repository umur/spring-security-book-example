package com.example.security.mfa.config;

import com.example.security.mfa.model.AppUser;
import com.example.security.mfa.repository.AppUserRepository;
import com.example.security.mfa.service.MfaService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataSeeder implements ApplicationRunner {

    private final AppUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final MfaService mfaService;

    @Override
    public void run(ApplicationArguments args) {
        if (userRepository.count() > 0) {
            return;
        }

        // admin — MFA enabled
        AppUser admin = AppUser.builder()
                .username("admin")
                .password(passwordEncoder.encode("admin"))
                .role("ADMIN")
                .mfaEnabled(false)
                .build();
        userRepository.save(admin);
        var setup = mfaService.setupMfa("admin");
        log.info("Admin MFA secret: {}", setup.secret());

        // user — MFA not enabled
        AppUser user = AppUser.builder()
                .username("user")
                .password(passwordEncoder.encode("user"))
                .role("USER")
                .mfaEnabled(false)
                .build();
        userRepository.save(user);

        log.info("Seeded users: admin (MFA enabled), user (MFA disabled)");
    }
}
