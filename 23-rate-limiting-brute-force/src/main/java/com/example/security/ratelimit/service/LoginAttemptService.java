package com.example.security.ratelimit.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks failed login attempts per username using an in-memory ConcurrentHashMap.
 * Accounts are locked after {@code maxAttempts} failures and auto-unlock after
 * {@code lockDurationSeconds} seconds.
 */
@Service
public class LoginAttemptService {

    private final int maxAttempts;
    private final long lockDurationSeconds;

    record AttemptRecord(int count, Instant lockedAt) {}

    private final ConcurrentHashMap<String, AttemptRecord> attemptCache = new ConcurrentHashMap<>();

    public LoginAttemptService(
            @Value("${app.security.max-attempts:5}") int maxAttempts,
            @Value("${app.security.lock-duration-seconds:900}") long lockDurationSeconds) {
        this.maxAttempts = maxAttempts;
        this.lockDurationSeconds = lockDurationSeconds;
    }

    public void recordFailure(String username) {
        attemptCache.compute(username, (key, existing) -> {
            int newCount = (existing == null ? 0 : existing.count()) + 1;
            Instant lockedAt = newCount >= maxAttempts ? Instant.now() : null;
            return new AttemptRecord(newCount, lockedAt);
        });
    }

    public void recordSuccess(String username) {
        attemptCache.remove(username);
    }

    public boolean isLocked(String username) {
        AttemptRecord record = attemptCache.get(username);
        if (record == null || record.lockedAt() == null) {
            return false;
        }
        if (Instant.now().isAfter(record.lockedAt().plusSeconds(lockDurationSeconds))) {
            attemptCache.remove(username);
            return false;
        }
        return true;
    }

    public int getFailureCount(String username) {
        AttemptRecord record = attemptCache.get(username);
        return record == null ? 0 : record.count();
    }

    public Instant getLockExpiry(String username) {
        AttemptRecord record = attemptCache.get(username);
        if (record == null || record.lockedAt() == null) {
            return null;
        }
        return record.lockedAt().plusSeconds(lockDurationSeconds);
    }

    /** Visible for testing: directly inject a lock record with a custom lock time. */
    public void forceLock(String username, Instant lockedAt) {
        attemptCache.put(username, new AttemptRecord(maxAttempts, lockedAt));
    }

    /** Visible for testing: clear all records. */
    public void reset() {
        attemptCache.clear();
    }

    public int getMaxAttempts() {
        return maxAttempts;
    }

    public AccountStatusResponse getAccountStatus(String username) {
        return new AccountStatusResponse(
                username,
                isLocked(username),
                getFailureCount(username),
                getLockExpiry(username)
        );
    }
}
