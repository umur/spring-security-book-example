package com.example.security.auditing.controller;

import com.example.security.auditing.service.ProfileService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/profile")
@RequiredArgsConstructor
public class ProfileController {

    private final ProfileService profileService;

    @GetMapping
    public ResponseEntity<ProfileService.ProfileResponse> getProfile(
            @AuthenticationPrincipal UserDetails principal,
            HttpServletRequest request) {
        return ResponseEntity.ok(profileService.getProfile(principal, request.getRemoteAddr()));
    }
}
