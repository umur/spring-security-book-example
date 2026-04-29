package com.example.security.mfa.service;

import com.example.security.mfa.model.AppUser;
import com.example.security.mfa.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class MfaService {

    private final AppUserRepository userRepository;
    private final TotpService totpService;

    public record MfaSetupResult(String secret, String qrCodeUrl) {}

    @Transactional
    public MfaSetupResult setupMfa(String username) {
        AppUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        String secret = totpService.generateSecret();
        String qrCodeUrl = totpService.buildQrCodeUrl(username, secret);

        user.setMfaSecret(secret);
        user.setMfaEnabled(true);
        userRepository.save(user);

        return new MfaSetupResult(secret, qrCodeUrl);
    }

    public boolean verifyTotp(String username, int code) {
        AppUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        if (!user.isMfaEnabled() || user.getMfaSecret() == null) {
            return false;
        }

        return totpService.verifyCode(user.getMfaSecret(), code);
    }

    public boolean isMfaEnabled(String username) {
        return userRepository.findByUsername(username)
                .map(AppUser::isMfaEnabled)
                .orElse(false);
    }
}
