package com.example.security.methodsecurity.service;

import com.example.security.methodsecurity.model.Document;
import com.example.security.methodsecurity.repository.DocumentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Service layer carrying all method-security annotations.
 * Placing the annotations here (rather than on the controller) ensures they are
 * enforced regardless of how the service is called — via HTTP, messaging, scheduled
 * jobs, or internal callers — and keeps security concerns out of the web layer.
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class DocumentService {

    private final DocumentRepository documentRepository;

    /**
     * GET /api/documents — any authenticated user may invoke this method.
     * @PostFilter trims the result list so that non-admin callers only see documents
     * they own. ADMIN callers receive the full list.
     */
    @PostFilter("filterObject.owner == authentication.name or hasRole('ADMIN')")
    public List<Document> findAll() {
        return documentRepository.findAll();
    }

    /**
     * GET /api/documents/{id} — any authenticated user may invoke this method.
     * @PostAuthorize verifies the returned object belongs to the caller (or that
     * the caller is ADMIN) *after* the database read, ensuring no data leaks.
     */
    @PostAuthorize("returnObject.owner == authentication.name or hasRole('ADMIN')")
    public Document findById(Long id) {
        return documentRepository.findById(id)
                .orElseThrow(() -> new DocumentNotFoundException(id));
    }

    /**
     * POST /api/documents — any authenticated user may create a document.
     * No additional method-security annotation needed; the security filter chain
     * already requires authentication for all /api/** paths.
     */
    @Transactional
    public Document create(Document document) {
        return documentRepository.save(document);
    }

    /**
     * PUT /api/documents/{id} — only the owner or ADMIN may update.
     * The check delegates to the {@link DocumentSecurity} bean so the SpEL
     * expression stays concise and the logic is independently testable.
     */
    @PreAuthorize("@documentSecurity.isOwner(#id, authentication)")
    @Transactional
    public Document update(Long id, String title, String content) {
        Document doc = documentRepository.findById(id)
                .orElseThrow(() -> new DocumentNotFoundException(id));
        doc.setTitle(title);
        doc.setContent(content);
        return documentRepository.save(doc);
    }

    /**
     * DELETE /api/documents/{id} — ADMIN only.
     */
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public void delete(Long id) {
        if (!documentRepository.existsById(id)) {
            throw new DocumentNotFoundException(id);
        }
        documentRepository.deleteById(id);
    }

    /**
     * Demonstrates @PreFilter: filters an incoming list so only documents owned
     * by the caller (or ADMIN) are processed before the method body executes.
     * The {@code filterTarget} attribute names the parameter to filter when the
     * method has more than one parameter.
     */
    @PreFilter(value = "filterObject.owner == authentication.name or hasRole('ADMIN')",
               filterTarget = "documents")
    @Transactional
    public List<Document> bulkUpdate(List<Document> documents) {
        return documentRepository.saveAll(documents);
    }

    // ---------------------------------------------------------------------------
    // Exception
    // ---------------------------------------------------------------------------

    public static class DocumentNotFoundException extends RuntimeException {
        public DocumentNotFoundException(Long id) {
            super("Document not found: " + id);
        }
    }
}
