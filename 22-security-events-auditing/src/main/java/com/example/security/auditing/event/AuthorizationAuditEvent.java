package com.example.security.auditing.event;

import org.springframework.context.ApplicationEvent;

/**
 * Custom application event published when an authorization decision is made.
 */
public class AuthorizationAuditEvent extends ApplicationEvent {

    private final String username;
    private final String resource;
    private final boolean granted;
    private final String ipAddress;

    public AuthorizationAuditEvent(Object source, String username, String resource,
                                   boolean granted, String ipAddress) {
        super(source);
        this.username = username;
        this.resource = resource;
        this.granted = granted;
        this.ipAddress = ipAddress;
    }

    public String getUsername() {
        return username;
    }

    public String getResource() {
        return resource;
    }

    public boolean isGranted() {
        return granted;
    }

    public String getIpAddress() {
        return ipAddress;
    }
}
