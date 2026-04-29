package com.example.security.redissession.controller;

import com.example.security.redissession.dto.SessionInfoResponse;
import com.example.security.redissession.dto.SetAttributeRequest;
import com.example.security.redissession.dto.SetAttributeResponse;
import com.example.security.redissession.service.SessionInfoService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/session")
@RequiredArgsConstructor
public class SessionApiController {

    private final SessionInfoService sessionInfoService;

    @GetMapping("/info")
    ResponseEntity<SessionInfoResponse> sessionInfo(@AuthenticationPrincipal UserDetails user,
                                                    HttpSession session) {
        return ResponseEntity.ok(sessionInfoService.buildSessionInfo(user, session));
    }

    @PostMapping("/attribute")
    ResponseEntity<SetAttributeResponse> setAttribute(@RequestBody SetAttributeRequest request,
                                                      HttpSession session) {
        return ResponseEntity.ok(sessionInfoService.setAttribute(session, request.name(), request.value()));
    }
}
