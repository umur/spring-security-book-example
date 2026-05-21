package com.cinetrack.recommendation;

/**
 * DTO representing the movie data received from catalog-service.
 * Kept intentionally minimal: recommendation-service only needs id, title, and year.
 */
public record CatalogMovie(Long id, String title, int year) {
}
