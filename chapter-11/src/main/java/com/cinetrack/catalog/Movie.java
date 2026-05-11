package com.cinetrack.catalog;

/**
 * Catalog movie record — the domain object returned by CatalogController.
 */
public record Movie(Long id, String title, int year, String genre) {
}
