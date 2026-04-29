package com.example.security.redissession.service;

import com.example.security.redissession.dto.SessionInfoResponse;
import com.example.security.redissession.dto.SetAttributeResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.Instant;

/**
 * Service layer responsible for extracting and assembling session metadata.
 * Controllers remain thin delegating all logic here.
 */
@Service
public class SessionInfoService {

    public SessionInfoResponse buildSessionInfo(UserDetails user, HttpSession session) {
        return new SessionInfoResponse(
                user.getUsername(),
                session.getId(),
                Instant.ofEpochMilli(session.getCreationTime()).toString(),
                Instant.ofEpochMilli(session.getLastAccessedTime()).toString(),
                session.getMaxInactiveInterval(),
                user.getAuthorities().stream()
                        .map(a -> a.getAuthority())
                        .toList()
        );
    }

    public SetAttributeResponse setAttribute(HttpSession session, String name, String value) {
        session.setAttribute(name, value);
        return new SetAttributeResponse(name, value, session.getId());
    }
}
