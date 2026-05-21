package com.cinetrack.review;

/**
 * Immutable value representing a single review entry.
 *
 * {@code authorUsername} is the field inspected by {@code @PostFilter} and
 * {@code @PostAuthorize} expressions to enforce ownership semantics after the
 * method returns its result.
 */
public record Review(Long id, Long movieId, String authorUsername, String content) {
}
