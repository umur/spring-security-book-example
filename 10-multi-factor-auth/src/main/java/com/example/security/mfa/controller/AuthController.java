package com.example.security.mfa.controller;

import com.example.security.mfa.service.AuthService;
import com.example.security.mfa.service.AuthService.LoginResult;
import com.example.security.mfa.service.MfaService;
import com.example.security.mfa.service.MfaService.MfaSetupResult;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final MfaService mfaService;

    public record LoginRequest(String username, String password) {}
    public record LoginResponse(boolean mfaRequired, String tempToken, String sessionToken, String username) {}
    public record VerifyMfaRequest(String tempToken, int totpCode) {}
    public record VerifyMfaResponse(String sessionToken) {}
    public record MfaSetupResponse(String secret, String qrCodeUrl) {}

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        LoginResult result = authService.login(request.username(), request.password());
        return ResponseEntity.ok(new LoginResponse(
                result.mfaRequired(),
                result.tempToken(),
                result.sessionToken(),
                result.username()
        ));
    }

    @PostMapping("/verify-mfa")
    public ResponseEntity<VerifyMfaResponse> verifyMfa(@RequestBody VerifyMfaRequest request) {
        String sessionToken = authService.verifyMfa(request.tempToken(), request.totpCode());
        return ResponseEntity.ok(new VerifyMfaResponse(sessionToken));
    }

    @PostMapping("/mfa/setup")
    public ResponseEntity<MfaSetupResponse> setupMfa(Authentication authentication) {
        MfaSetupResult result = mfaService.setupMfa(authentication.getName());
        return ResponseEntity.ok(new MfaSetupResponse(result.secret(), result.qrCodeUrl()));
    }
}
