package com.example.security.redissession.controller;

import com.example.security.redissession.service.SessionInfoService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class DashboardController {

    private final SessionInfoService sessionInfoService;

    @GetMapping("/dashboard")
    String dashboard(@AuthenticationPrincipal UserDetails user,
                     HttpSession session,
                     Model model) {
        model.addAttribute("info", sessionInfoService.buildSessionInfo(user, session));
        return "dashboard";
    }
}
