package com.cinetrack.catalog;

/**
 * Minimal movie record returned by the catalog-service API.
 */
public record Movie(Long id, String title, int year) {
}
