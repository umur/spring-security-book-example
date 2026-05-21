package com.cinetrack.movie;

/**
 * Immutable value carrying the movie data passed into method-security expressions.
 *
 * {@code premiumOnly} is the field that drives the SpEL expression in
 * {@code MovieService#getMovie}: non-premium users are blocked at the AOP proxy
 * before the method body even executes.
 */
public record Movie(Long id, String title, boolean premiumOnly) {
}
