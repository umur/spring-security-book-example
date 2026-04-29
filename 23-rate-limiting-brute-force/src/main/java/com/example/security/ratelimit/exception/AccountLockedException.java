package com.example.security.ratelimit.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown when a login attempt is rejected because the account is locked.
 */
public class AccountLockedException extends AuthenticationException {

    public AccountLockedException(String message) {
        super(message);
    }
}
