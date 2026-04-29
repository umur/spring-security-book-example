package com.example.security.apikey.service;

import com.example.security.apikey.model.ApiKey;
import com.example.security.apikey.repository.ApiKeyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class ApiKeyService {

    private static final int KEY_BYTES = 32;
    private final ApiKeyRepository apiKeyRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecureRandom secureRandom = new SecureRandom();

    public record GeneratedApiKey(String rawKey, ApiKey savedEntity) {}

    public GeneratedApiKey generate(String owner, String roles) {
        byte[] bytes = new byte[KEY_BYTES];
        secureRandom.nextBytes(bytes);
        String rawKey = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        String hash = passwordEncoder.encode(rawKey);
        ApiKey entity = apiKeyRepository.save(new ApiKey(hash, owner, roles));
        return new GeneratedApiKey(rawKey, entity);
    }

    public Optional<ApiKey> validate(String rawKey) {
        List<ApiKey> active = apiKeyRepository.findAllByActiveTrue();
        return active.stream()
                .filter(k -> passwordEncoder.matches(rawKey, k.getKeyHash()))
                .findFirst();
    }

    public List<String> parseRoles(ApiKey apiKey) {
        return Arrays.stream(apiKey.getRoles().split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .toList();
    }
}
