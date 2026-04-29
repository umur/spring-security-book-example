package com.example.security.ldap.controller;

import com.example.security.ldap.service.LdapUserService;
import com.example.security.ldap.service.LdapUserService.UserProfile;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class LdapController {

    private final LdapUserService ldapUserService;

    @GetMapping("/profile")
    public ResponseEntity<UserProfile> getProfile(Authentication authentication) {
        return ResponseEntity.ok(ldapUserService.getProfile(authentication));
    }

    @GetMapping("/admin")
    public ResponseEntity<Map<String, String>> adminEndpoint(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "Admin area",
                "user", authentication.getName()
        ));
    }
}
