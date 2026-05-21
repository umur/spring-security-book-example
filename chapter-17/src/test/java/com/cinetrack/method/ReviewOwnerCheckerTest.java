package com.cinetrack.method;

import com.cinetrack.review.ReviewOwnerChecker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ReviewOwnerChecker}.
 *
 * No Spring context is needed: the bean has no dependencies beyond its own
 * in-memory map, so a plain instantiation is sufficient.
 */
class ReviewOwnerCheckerTest {

    private ReviewOwnerChecker checker;

    @BeforeEach
    void setUp() {
        checker = new ReviewOwnerChecker();
        checker.register(1L, "alice");
        checker.register(2L, "bob");
    }

    @Test
    void isOwner_returnsTrueWhenPrincipalMatchesAuthor() {
        Authentication alice = new UsernamePasswordAuthenticationToken("alice", null, List.of());
        assertThat(checker.isOwner(alice, 1L)).isTrue();
    }

    @Test
    void isOwner_returnsFalseWhenPrincipalDiffersFromAuthor() {
        Authentication bob = new UsernamePasswordAuthenticationToken("bob", null, List.of());
        assertThat(checker.isOwner(bob, 1L)).isFalse();
    }

    @Test
    void isOwner_returnsFalseForUnknownReviewId() {
        Authentication alice = new UsernamePasswordAuthenticationToken("alice", null, List.of());
        assertThat(checker.isOwner(alice, 999L)).isFalse();
    }

    @Test
    void isOwner_returnsTrueForBobOnBobsReview() {
        Authentication bob = new UsernamePasswordAuthenticationToken("bob", null, List.of());
        assertThat(checker.isOwner(bob, 2L)).isTrue();
    }
}
