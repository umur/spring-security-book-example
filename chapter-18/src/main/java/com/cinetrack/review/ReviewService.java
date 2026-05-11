package com.cinetrack.review;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Demonstrates per-object authorization using Spring Security ACL.
 *
 * When a review is created, an ACL object identity is registered and the author
 * is granted READ, WRITE, and DELETE permissions. Subsequent reads and mutations
 * go through {@code @PostAuthorize} / {@code @PreAuthorize} with
 * {@code hasPermission()} expressions, which delegate to the
 * {@code AclPermissionEvaluator} wired in {@code AclConfig}.
 *
 * The two hasPermission overloads:
 *   - {@code hasPermission(returnObject, 'READ')}         — domain object form
 *   - {@code hasPermission(#id, 'com.cinetrack.Review', 'DELETE')} — id + type form
 */
@Service
public class ReviewService {

    private final ReviewRepository reviewRepository;
    private final MutableAclService aclService;

    public ReviewService(ReviewRepository reviewRepository, MutableAclService aclService) {
        this.reviewRepository = reviewRepository;
        this.aclService = aclService;
    }

    /**
     * Persists the review and immediately grants the author READ, WRITE, and
     * DELETE on the new ACL object identity. No security annotation is needed
     * here — any authenticated user may submit a review.
     */
    @Transactional
    public Review createReview(Review review) {
        Review saved = reviewRepository.save(review);
        grantOwnerPermissions(saved);
        return saved;
    }

    /**
     * Returns a review only when the caller holds the READ permission in the ACL
     * for this specific review instance. {@code @PostAuthorize} runs after the
     * method returns, so {@code returnObject} is available in the expression.
     */
    @PostAuthorize("hasPermission(returnObject, 'READ')")
    @Transactional(readOnly = true)
    public Review getReview(Long id) {
        return reviewRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Review not found: " + id));
    }

    /**
     * Updates the review content. The caller must hold the WRITE permission on
     * the review object. {@code #review} refers to the method parameter.
     */
    @PreAuthorize("hasPermission(#review, 'WRITE')")
    @Transactional
    public Review updateReview(Review review) {
        Review existing = reviewRepository.findById(review.getId())
                .orElseThrow(() -> new IllegalArgumentException("Review not found: " + review.getId()));
        existing.setContent(review.getContent());
        return reviewRepository.save(existing);
    }

    /**
     * Deletes the review. Uses the id + type form of {@code hasPermission} so
     * Spring Security resolves the ACL by class name and object id without
     * needing to load the entity first.
     */
    @PreAuthorize("hasPermission(#reviewId, 'com.cinetrack.review.Review', 'DELETE')")
    @Transactional
    public void deleteReview(Long reviewId) {
        reviewRepository.deleteById(reviewId);
        ObjectIdentity oid = new ObjectIdentityImpl(Review.class, reviewId);
        aclService.deleteAcl(oid, true);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void grantOwnerPermissions(Review review) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Sid owner = new PrincipalSid(auth.getName());
        ObjectIdentity oid = new ObjectIdentityImpl(Review.class, review.getId());

        MutableAcl acl = aclService.createAcl(oid);
        acl.insertAce(acl.getEntries().size(), BasePermission.READ,   owner, true);
        acl.insertAce(acl.getEntries().size(), BasePermission.WRITE,  owner, true);
        acl.insertAce(acl.getEntries().size(), BasePermission.DELETE, owner, true);
        // any authenticated user with ROLE_USER may read the review
        Sid roleUser = new GrantedAuthoritySid("ROLE_USER");
        acl.insertAce(acl.getEntries().size(), BasePermission.READ,   roleUser, true);
        aclService.updateAcl(acl);
    }
}
