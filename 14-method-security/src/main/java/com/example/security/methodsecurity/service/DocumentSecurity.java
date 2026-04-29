package com.example.security.methodsecurity.service;

import com.example.security.methodsecurity.repository.DocumentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

/**
 * Named security bean referenced in SpEL expressions via @PreAuthorize("@documentSecurity.isOwner(...)").
 * Keeping authorization logic in a dedicated component keeps controller code clean and makes
 * the rules independently testable.
 */
@Component("documentSecurity")
@RequiredArgsConstructor
public class DocumentSecurity {

    private final DocumentRepository documentRepository;

    /**
     * Returns true when the authenticated principal is the owner of the document
     * identified by {@code documentId}, or when the principal holds ROLE_ADMIN.
     */
    public boolean isOwner(Long documentId, Authentication authentication) {
        if (authentication == null) {
            return false;
        }
        boolean isAdmin = authentication.getAuthorities()
                .contains(new SimpleGrantedAuthority("ROLE_ADMIN"));
        if (isAdmin) {
            return true;
        }
        return documentRepository.findById(documentId)
                .map(doc -> doc.getOwner().equals(authentication.getName()))
                .orElse(false);
    }
}
