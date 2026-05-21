package com.cinetrack.method;

import com.cinetrack.movie.Movie;
import com.cinetrack.movie.MovieService;
import com.cinetrack.review.Review;
import com.cinetrack.review.ReviewService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.test.context.support.WithMockUser;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Verifies that method-security annotations enforce the correct authorization
 * decisions at the service layer, independent of any HTTP transport.
 *
 * {@code @SpringBootTest} loads the full application context so that the AOP
 * proxies wrapping the service beans are actually active. {@code @WithMockUser}
 * injects a synthetic {@code Authentication} into the {@code SecurityContext}
 * for the duration of each test method.
 */
@SpringBootTest
class MethodSecurityTest {

    @Autowired
    private MovieService movieService;

    @Autowired
    private ReviewService reviewService;

    private static final Movie PREMIUM_MOVIE = new Movie(1L, "Inception", true);
    private static final Movie FREE_MOVIE    = new Movie(2L, "Big Buck Bunny", false);

    @BeforeEach
    @WithMockUser(username = "alice", authorities = {"ROLE_VIEWER", "TIER_PREMIUM"})
    void seedReviews() {
        reviewService.createReview(new Review(null, 10L, "alice", "Great film!"));
        reviewService.createReview(new Review(null, 10L, "alice", "Rewatched it."));
    }

    // -------------------------------------------------------------------------
    // MovieService: @PreAuthorize with compound SpEL
    // -------------------------------------------------------------------------

    @Test
    @WithMockUser(username = "alice", authorities = {"ROLE_VIEWER", "TIER_PREMIUM"})
    void premiumUser_canGetPremiumMovie() {
        Movie result = movieService.getMovie(PREMIUM_MOVIE);
        assertThat(result.title()).isEqualTo("Inception");
    }

    @Test
    @WithMockUser(username = "bob", authorities = {"ROLE_VIEWER", "TIER_BASIC"})
    void basicUser_cannotGetPremiumMovie_throwsAccessDenied() {
        assertThatThrownBy(() -> movieService.getMovie(PREMIUM_MOVIE))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @WithMockUser(username = "bob", authorities = {"ROLE_VIEWER", "TIER_BASIC"})
    void basicUser_canGetFreeMovie() {
        Movie result = movieService.getMovie(FREE_MOVIE);
        assertThat(result.title()).isEqualTo("Big Buck Bunny");
    }

    // -------------------------------------------------------------------------
    // ReviewService: @PostFilter
    // -------------------------------------------------------------------------

    @Test
    @WithMockUser(username = "alice", authorities = {"ROLE_VIEWER", "TIER_PREMIUM"})
    void getReviews_forAlice_returnsOnlyHerOwnReviews() {
        List<Review> reviews = reviewService.getReviews(10L);

        assertThat(reviews).isNotEmpty();
        assertThat(reviews).allMatch(r -> r.authorUsername().equals("alice"));
    }

    @Test
    @WithMockUser(username = "bob", authorities = {"ROLE_VIEWER", "TIER_BASIC"})
    void getReviews_forBob_returnsEmptyListBecauseHeOwnsNone() {
        // Bob authored no reviews for movie 10: PostFilter removes everything
        List<Review> reviews = reviewService.getReviews(10L);
        assertThat(reviews).isEmpty();
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN", "VIEWER"})
    void getReviews_forAdmin_returnsAllReviews() {
        List<Review> reviews = reviewService.getReviews(10L);
        assertThat(reviews).hasSizeGreaterThanOrEqualTo(2);
    }

    // -------------------------------------------------------------------------
    // ReviewService: @PostAuthorize
    // -------------------------------------------------------------------------

    @Test
    @WithMockUser(username = "alice", authorities = {"ROLE_VIEWER", "TIER_PREMIUM"})
    void getReview_byOwner_returnsReview() {
        // Seed a review owned by alice and fetch it back
        Review created = reviewService.createReview(new Review(null, 20L, "alice", "Loved it"));
        Review fetched = reviewService.getReview(created.id());
        assertThat(fetched.authorUsername()).isEqualTo("alice");
    }

    @Test
    @WithMockUser(username = "bob", authorities = {"ROLE_VIEWER", "TIER_BASIC"})
    void getReview_byNonOwner_throwsAccessDenied() {
        // alice created this review; bob tries to read it
        Review alicesReview = reviewService.createReview(
                new Review(null, 20L, "alice", "Bob cannot see this"));

        // Switch to bob's context: @WithMockUser applies to the test method
        // so the createReview above runs as alice only if we seed in @BeforeEach.
        // Here we simulate: store already has alice's review with id, bob reads it.
        assertThatThrownBy(() -> reviewService.getReview(alicesReview.id()))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN", "VIEWER"})
    void getReview_byAdmin_canReadAnyReview() {
        Review created = reviewService.createReview(new Review(null, 30L, "admin", "Admin review"));
        Review fetched = reviewService.getReview(created.id());
        assertThat(fetched).isNotNull();
    }
}
