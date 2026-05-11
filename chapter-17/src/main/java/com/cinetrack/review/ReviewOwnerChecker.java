package com.cinetrack.review;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Custom SpEL bean referenced in {@code @PreAuthorize} as
 * {@code @reviewOwnerChecker.isOwner(authentication, #reviewId)}.
 *
 * Spring Security evaluates SpEL beans by resolving the {@code @beanName}
 * prefix against the application context, then calling the method. This lets
 * you inject any repository or service logic into the authorization decision
 * without coupling it to the annotation string.
 *
 * This implementation keeps an in-memory author map so the chapter has no
 * database dependency, but in production you would call a {@code ReviewRepository}
 * here instead.
 */
@Component("reviewOwnerChecker")
public class ReviewOwnerChecker {

    private final Map<Long, String> reviewAuthors = new ConcurrentHashMap<>();

    /**
     * Registers a review author so subsequent {@code isOwner} calls can resolve
     * ownership. Call this after persisting a review.
     */
    public void register(Long reviewId, String username) {
        reviewAuthors.put(reviewId, username);
    }

    /**
     * Returns {@code true} when the authenticated principal created the review.
     *
     * @param auth     the current security context principal
     * @param reviewId the review being acted upon
     */
    public boolean isOwner(Authentication auth, Long reviewId) {
        String author = reviewAuthors.get(reviewId);
        return author != null && author.equals(auth.getName());
    }
}
