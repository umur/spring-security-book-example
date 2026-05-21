package com.cinetrack.catalog;

/**
 * Movie record returned by catalog-service.
 */
public record Movie(String id, String title, String genre) {
}
