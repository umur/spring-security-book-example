package com.example.security.auditing.service;

import com.example.security.auditing.event.AuthorizationAuditEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class ProfileService {

    private final ApplicationEventPublisher eventPublisher;

    public record ProfileResponse(String username, List<String> roles) {}

    public ProfileResponse getProfile(UserDetails principal, String ipAddress) {
        eventPublisher.publishEvent(new AuthorizationAuditEvent(
                this,
                principal.getUsername(),
                "/api/profile",
                true,
                ipAddress
        ));
        List<String> roles = principal.getAuthorities().stream()
                .map(a -> a.getAuthority())
                .toList();
        return new ProfileResponse(principal.getUsername(), roles);
    }
}
