package com.example.security.auditing.service;

import com.example.security.auditing.event.AuthorizationAuditEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

/**
 * Listens to Spring Security authentication events and custom authorization events,
 * persisting them to the audit trail via AuditService.
 */
@Component
@RequiredArgsConstructor
public class SecurityEventListener {

    private final AuditService auditService;

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        String username = event.getAuthentication().getName();
        auditService.recordEvent(
                "AUTH_SUCCESS",
                username,
                extractIpFromDetails(event.getAuthentication().getDetails()),
                "Authentication succeeded"
        );
    }

    @EventListener
    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
        String username = String.valueOf(event.getAuthentication().getPrincipal());
        auditService.recordEvent(
                "AUTH_FAILURE",
                username,
                extractIpFromDetails(event.getAuthentication().getDetails()),
                "Bad credentials: " + event.getException().getMessage()
        );
    }

    @EventListener
    public void onAuthorizationAudit(AuthorizationAuditEvent event) {
        String eventType = event.isGranted() ? "AUTHZ_GRANTED" : "AUTHZ_DENIED";
        auditService.recordEvent(
                eventType,
                event.getUsername(),
                event.getIpAddress(),
                "Resource: " + event.getResource()
        );
    }

    private String extractIpFromDetails(Object details) {
        if (details instanceof org.springframework.security.web.authentication.WebAuthenticationDetails web) {
            return web.getRemoteAddress();
        }
        return "unknown";
    }
}
