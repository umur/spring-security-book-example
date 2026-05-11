package com.cinetrack.recommendation;

/**
 * Minimal movie projection returned by the recommendation feed.
 */
public record Movie(String id, String title, String genre, double rating) {
}
