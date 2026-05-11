package com.cinetrack.review;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * JPA entity representing a user review.
 *
 * The generated {@code id} is the object identity key used throughout the ACL
 * tables. When an ACL entry is created for this review, the ACL service stores
 * this id in {@code acl_object_identity.object_id_identity}.
 */
@Entity
@Table(name = "reviews")
public class Review {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long movieId;
    private String authorUsername;
    private String content;

    protected Review() {
    }

    public Review(Long movieId, String authorUsername, String content) {
        this.movieId = movieId;
        this.authorUsername = authorUsername;
        this.content = content;
    }

    public Long getId() {
        return id;
    }

    public Long getMovieId() {
        return movieId;
    }

    public String getAuthorUsername() {
        return authorUsername;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }
}
