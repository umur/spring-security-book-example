package com.example.security.ratelimit.service;

import com.example.security.ratelimit.exception.AccountLockedException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

/**
 * Orchestrates login: delegates credential verification to AuthenticationManager,
 * then instructs LoginAttemptService to record the outcome.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final LoginAttemptService loginAttemptService;

    /**
     * Attempts authentication for the given credentials.
     *
     * @return a LoginResponse with success message and username
     * @throws AccountLockedException  if the account is currently locked
     * @throws AuthenticationException if credentials are wrong
     */
    public LoginResponse login(String username, String password) {
        if (loginAttemptService.isLocked(username)) {
            throw new AccountLockedException("Account is locked due to too many failed attempts");
        }
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));
            loginAttemptService.recordSuccess(username);
            return new LoginResponse("Login successful", auth.getName());
        } catch (AuthenticationException ex) {
            loginAttemptService.recordFailure(username);
            throw ex;
        }
    }
}
