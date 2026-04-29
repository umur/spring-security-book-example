package com.example.security.ratelimit.controller;

import com.example.security.ratelimit.service.AccountStatusResponse;
import com.example.security.ratelimit.service.LoginAttemptService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/account")
@RequiredArgsConstructor
public class AccountStatusController {

    private final LoginAttemptService loginAttemptService;

    @GetMapping("/status")
    public ResponseEntity<AccountStatusResponse> getAccountStatus(@RequestParam String username) {
        return ResponseEntity.ok(loginAttemptService.getAccountStatus(username));
    }
}
