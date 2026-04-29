package com.example.security.auditing.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "audit_events")
@Getter
@Setter
@NoArgsConstructor
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String eventType;

    @Column(nullable = false)
    private String username;

    @Column
    private String ipAddress;

    @Column(length = 1000)
    private String details;

    @Column(nullable = false)
    private Instant timestamp;

    public AuditEvent(String eventType, String username, String ipAddress, String details) {
        this.eventType = eventType;
        this.username = username;
        this.ipAddress = ipAddress;
        this.details = details;
        this.timestamp = Instant.now();
    }
}
