package com.cinetrack.review;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

/**
 * REST facade for review operations.
 *
 * URL-level security is intentionally coarse: any authenticated user can call
 * any endpoint. The per-object READ / WRITE / DELETE enforcement lives entirely
 * in {@link ReviewService} via {@code @PostAuthorize} and {@code @PreAuthorize}
 * with {@code hasPermission()} expressions — this controller just translates
 * HTTP to service calls and back.
 */
@RestController
@RequestMapping("/api/reviews")
public class ReviewController {

    private final ReviewService reviewService;

    public ReviewController(ReviewService reviewService) {
        this.reviewService = reviewService;
    }

    // POST /api/reviews — any authenticated user may submit a review
    @PostMapping
    public ResponseEntity<Review> create(@RequestBody ReviewRequest request,
                                         Authentication authentication) {
        Review review = new Review(
                request.movieId(),
                authentication.getName(),
                request.content()
        );
        Review saved = reviewService.createReview(review);
        return ResponseEntity
                .created(URI.create("/api/reviews/" + saved.getId()))
                .body(saved);
    }

    // GET /api/reviews/{id} — ACL READ enforced by @PostAuthorize in the service
    @GetMapping("/{id}")
    public ResponseEntity<Review> get(@PathVariable Long id) {
        return ResponseEntity.ok(reviewService.getReview(id));
    }

    // DELETE /api/reviews/{id} — ACL DELETE enforced by @PreAuthorize in the service
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        reviewService.deleteReview(id);
        return ResponseEntity.noContent().build();
    }

    // Inline DTO so the controller package stays self-contained
    public record ReviewRequest(Long movieId, String content) {}
}
