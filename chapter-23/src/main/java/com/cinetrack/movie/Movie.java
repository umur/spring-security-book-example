package com.cinetrack.movie;

/**
 * Minimal movie record for the catalog API.
 */
public record Movie(Long id, String title, int year) {
}
