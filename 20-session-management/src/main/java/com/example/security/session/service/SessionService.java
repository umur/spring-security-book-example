package com.example.security.session.service;

import com.example.security.session.dto.SessionInfoResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;

import java.time.Instant;

@Service
public class SessionService {

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

    public void populateDashboardModel(UserDetails user, HttpSession session, Model model) {
        model.addAttribute("username", user.getUsername());
        model.addAttribute("authorities", user.getAuthorities());
        model.addAttribute("sessionId", session.getId());
        model.addAttribute("creationTime",
                Instant.ofEpochMilli(session.getCreationTime()).toString());
        model.addAttribute("maxInactiveInterval", session.getMaxInactiveInterval());
    }
}
