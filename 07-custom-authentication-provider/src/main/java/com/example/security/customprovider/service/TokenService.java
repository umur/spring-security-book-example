package com.example.security.customprovider.service;

import com.example.security.customprovider.controller.TokenController.TokenResponse;
import com.example.security.customprovider.model.DomainToken;
import com.example.security.customprovider.repository.DomainTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final DomainTokenRepository domainTokenRepository;

    public TokenResponse generateToken(UserDetails principal) {
        String rawToken = "dtkn-" + UUID.randomUUID();
        String role = principal.getAuthorities().iterator().next().getAuthority()
                .replace("ROLE_", "");

        Instant now = Instant.now();
        Instant expiresAt = now.plus(24, ChronoUnit.HOURS);

        var domainToken = new DomainToken(rawToken, principal.getUsername(), role, now, expiresAt);
        domainTokenRepository.save(domainToken);

        return new TokenResponse(rawToken, principal.getUsername(), expiresAt.toString());
    }
}
