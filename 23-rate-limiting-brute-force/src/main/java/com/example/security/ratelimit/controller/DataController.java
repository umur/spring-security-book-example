package com.example.security.ratelimit.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/data")
public class DataController {

    @GetMapping
    public ResponseEntity<Map<String, String>> getData(@AuthenticationPrincipal UserDetails principal) {
        return ResponseEntity.ok(Map.of(
                "message", "Protected data",
                "username", principal.getUsername()
        ));
    }
}
