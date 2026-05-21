package com.cinetrack.catalog;

/**
 * Catalog movie: the domain object returned by CatalogController.
 */
public record Movie(String id, String title, String genre) {
}
