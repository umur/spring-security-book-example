package com.cinetrack.recommendation;

/**
 * A recommendation record wrapping a movie title with a reason string.
 */
public record Recommendation(Long movieId, String title, int year, String reason) {
}
