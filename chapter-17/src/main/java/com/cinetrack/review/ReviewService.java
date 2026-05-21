package com.cinetrack.review;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Demonstrates the four method-security annotations working together:
 *
 * <ul>
 *   <li>{@code @PreAuthorize} : gate the call before execution</li>
 *   <li>{@code @PostAuthorize}: gate the return value after execution</li>
 *   <li>{@code @PostFilter}   : filter a returned collection after execution</li>
 *   <li>SpEL bean reference   : delegate complex logic to {@code @reviewOwnerChecker}</li>
 * </ul>
 */
@Service
public class ReviewService {

    private final Map<Long, Review> store = new ConcurrentHashMap<>();
    private final AtomicLong sequence = new AtomicLong(1);
    private final ReviewOwnerChecker ownerChecker;

    public ReviewService(ReviewOwnerChecker ownerChecker) {
        this.ownerChecker = ownerChecker;
    }

    /**
     * Any VIEWER may submit a review. The role check happens before the method
     * runs: unauthenticated or ADMIN-only callers are rejected immediately.
     */
    @PreAuthorize("hasRole('VIEWER')")
    public Review createReview(Review review) {
        long id = sequence.getAndIncrement();
        Review saved = new Review(id, review.movieId(), review.authorUsername(), review.content());
        store.put(id, saved);
        ownerChecker.register(id, saved.authorUsername());
        return saved;
    }

    /**
     * Returns a review only when the caller is the author, or is an ADMIN.
     * {@code @PostAuthorize} runs after the method returns so the return value
     * is available as {@code returnObject} in the expression.
     */
    @PostAuthorize("returnObject.authorUsername() == authentication.name or hasRole('ADMIN')")
    public Review getReview(Long id) {
        Review review = store.get(id);
        if (review == null) {
            throw new IllegalArgumentException("Review not found: " + id);
        }
        return review;
    }

    /**
     * Returns all reviews for a movie, then filters the list so each caller
     * sees only their own reviews: unless they are an ADMIN.
     *
     * {@code @PostFilter} mutates the returned collection in place, removing
     * any element for which the expression evaluates to {@code false}.
     * {@code filterObject} refers to the current element being evaluated.
     */
    @PostFilter("filterObject.authorUsername() == authentication.name or hasRole('ADMIN')")
    public List<Review> getReviews(Long movieId) {
        List<Review> result = new ArrayList<>();
        for (Review r : store.values()) {
            if (r.movieId().equals(movieId)) {
                result.add(r);
            }
        }
        return result;
    }

    /**
     * Only the review author or an ADMIN may delete a review.
     * The SpEL bean reference {@code @reviewOwnerChecker} lets the expression
     * call arbitrary Java without embedding repository logic in the annotation.
     */
    @PreAuthorize("hasRole('ADMIN') or @reviewOwnerChecker.isOwner(authentication, #reviewId)")
    public void deleteReview(Long reviewId) {
        store.remove(reviewId);
    }
}
