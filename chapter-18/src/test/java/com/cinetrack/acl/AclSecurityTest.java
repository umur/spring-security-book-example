package com.cinetrack.acl;

import com.cinetrack.review.Review;
import com.cinetrack.review.ReviewRepository;
import com.cinetrack.review.ReviewService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.annotation.DirtiesContext;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Verifies that ACL entries drive per-object access decisions correctly.
 *
 * Each test is fully self-contained: it creates any data it needs, then asserts
 * the outcome. No test relies on state left by a previous test. When a test
 * needs to switch security contexts mid-method (e.g. alice creates, bob tries
 * to read), it does so programmatically via {@code SecurityContextHolder}.
 *
 * {@code @DirtiesContext} resets the Spring context — and therefore the ACL
 * tables — between tests so ACL rows from one test cannot influence another.
 */
@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class AclSecurityTest {

    @Autowired
    private ReviewService reviewService;

    @Autowired
    private ReviewRepository reviewRepository;

    // -------------------------------------------------------------------------
    // READ
    // -------------------------------------------------------------------------

    @Test
    @WithMockUser(username = "alice", roles = "VIEWER")
    void alice_canReadHerOwnReview_afterCreating() {
        Review created = reviewService.createReview(new Review(1L, "alice", "Great movie!"));

        Review fetched = reviewService.getReview(created.getId());

        assertThat(fetched.getAuthorUsername()).isEqualTo("alice");
        assertThat(fetched.getContent()).isEqualTo("Great movie!");
    }

    @Test
    void bob_cannotReadAlicesReview_accessDenied() {
        // Step 1: alice creates a review — she gets the ACL entry.
        setSecurityContext("alice", "ROLE_VIEWER");
        Review alicesReview = reviewService.createReview(new Review(2L, "alice", "Alice only"));
        Long reviewId = alicesReview.getId();

        // Step 2: switch to bob — bob has no ACL READ entry for this review.
        setSecurityContext("bob", "ROLE_VIEWER");
        assertThatThrownBy(() -> reviewService.getReview(reviewId))
                .isInstanceOf(AccessDeniedException.class);
    }

    // -------------------------------------------------------------------------
    // WRITE
    // -------------------------------------------------------------------------

    @Test
    @WithMockUser(username = "alice", roles = "VIEWER")
    void alice_canUpdateHerOwnReview() {
        Review created = reviewService.createReview(new Review(3L, "alice", "Original"));

        created.setContent("Updated");
        Review updated = reviewService.updateReview(created);

        assertThat(updated.getContent()).isEqualTo("Updated");
    }

    @Test
    void bob_cannotUpdateAlicesReview_throwsAccessDenied() {
        // Step 1: alice creates a review.
        setSecurityContext("alice", "ROLE_VIEWER");
        Review created = reviewService.createReview(new Review(4L, "alice", "Alice's take"));

        // Step 2: switch to bob — bob has no WRITE ACL entry.
        setSecurityContext("bob", "ROLE_VIEWER");
        created.setContent("Tampered");
        final Review toUpdate = created;
        assertThatThrownBy(() -> reviewService.updateReview(toUpdate))
                .isInstanceOf(AccessDeniedException.class);
    }

    // -------------------------------------------------------------------------
    // DELETE
    // -------------------------------------------------------------------------

    @Test
    @WithMockUser(username = "alice", roles = "VIEWER")
    void alice_canDeleteHerOwnReview() {
        Review created = reviewService.createReview(new Review(5L, "alice", "To be deleted"));
        // Expect no exception
        reviewService.deleteReview(created.getId());

        assertThat(reviewRepository.findById(created.getId())).isEmpty();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Installs a synthetic {@code Authentication} into the {@code SecurityContext}
     * so subsequent service calls run as the given user. Use instead of
     * {@code @WithMockUser} when a single test method needs to switch users.
     */
    private void setSecurityContext(String username, String... roles) {
        var authorities = java.util.Arrays.stream(roles)
                .map(SimpleGrantedAuthority::new)
                .collect(java.util.stream.Collectors.toList());
        var auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}
