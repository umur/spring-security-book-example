package com.example.security.oauth2login.controller;

import com.example.security.oauth2login.dto.DashboardInfo;
import com.example.security.oauth2login.service.UserInfoService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class PageController {

    private final UserInfoService userInfoService;

    @GetMapping("/")
    public String home() {
        return "redirect:/dashboard";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard(@AuthenticationPrincipal Object principal, Model model) {
        model.addAttribute("dashboardInfo", userInfoService.resolveDashboardInfo(principal));
        return "dashboard";
    }
}
