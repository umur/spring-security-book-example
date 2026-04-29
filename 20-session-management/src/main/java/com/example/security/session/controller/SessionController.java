package com.example.security.session.controller;

import com.example.security.session.dto.SessionInfoResponse;
import com.example.security.session.service.SessionService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class SessionController {

    private final SessionService sessionService;

    @GetMapping("/")
    String home() {
        return "redirect:/dashboard";
    }

    @GetMapping("/login")
    String login() {
        return "login";
    }

    @GetMapping("/dashboard")
    String dashboard(@AuthenticationPrincipal UserDetails user,
                     HttpSession session,
                     Model model) {
        sessionService.populateDashboardModel(user, session, model);
        return "dashboard";
    }

    @GetMapping("/api/session-info")
    @ResponseBody
    ResponseEntity<SessionInfoResponse> sessionInfo(@AuthenticationPrincipal UserDetails user,
                                                    HttpSession session) {
        return ResponseEntity.ok(sessionService.buildSessionInfo(user, session));
    }
}
