package com.example.security.auditing.service;

import com.example.security.auditing.model.AuditEvent;
import com.example.security.auditing.repository.AuditEventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditEventRepository auditEventRepository;

    public record AuditEventResponse(Long id, String eventType, String username,
                                     String ipAddress, String details, Instant timestamp) {
        static AuditEventResponse from(AuditEvent event) {
            return new AuditEventResponse(
                    event.getId(),
                    event.getEventType(),
                    event.getUsername(),
                    event.getIpAddress(),
                    event.getDetails(),
                    event.getTimestamp()
            );
        }
    }

    @Transactional
    public void recordEvent(String eventType, String username, String ipAddress, String details) {
        AuditEvent event = new AuditEvent(eventType, username, ipAddress, details);
        auditEventRepository.save(event);
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> getRecentEvents() {
        return auditEventRepository.findTop50ByOrderByTimestampDesc();
    }

    @Transactional(readOnly = true)
    public List<AuditEventResponse> getRecentEventResponses() {
        return auditEventRepository.findTop50ByOrderByTimestampDesc().stream()
                .map(AuditEventResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> getEventsByUsername(String username) {
        return auditEventRepository.findByUsernameOrderByTimestampDesc(username);
    }
}
