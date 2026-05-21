package com.cinetrack.recommendation;

/**
 * Minimal movie projection returned by the recommendation feed.
 *
 * A record suffices here: the recommendation service only projects what the
 * client needs to render a card; the full catalog lives in catalog-service.
 */
public record Movie(String id, String title, String genre, double rating) {
}
