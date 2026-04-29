package com.example.security.methodsecurity.controller;

import com.example.security.methodsecurity.model.Document;
import com.example.security.methodsecurity.service.DocumentService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/documents")
@RequiredArgsConstructor
public class DocumentController {

    private final DocumentService documentService;

    /**
     * GET /api/documents
     * Any authenticated user may call this; @PostFilter in the service trims results
     * so non-admins see only their own documents.
     */
    @GetMapping
    public List<DocumentResponse> listDocuments() {
        return documentService.findAll().stream()
                .map(DocumentResponse::from)
                .toList();
    }

    /**
     * GET /api/documents/{id}
     * @PostAuthorize in the service rejects the response if the caller is not the
     * owner and not an ADMIN.
     */
    @GetMapping("/{id}")
    public DocumentResponse getDocument(@PathVariable Long id) {
        return DocumentResponse.from(documentService.findById(id));
    }

    /**
     * POST /api/documents
     * Any authenticated user may create a document; ownership is set to the caller.
     */
    @PostMapping
    public ResponseEntity<DocumentResponse> createDocument(@RequestBody CreateDocumentRequest request,
                                                           @AuthenticationPrincipal UserDetails principal) {
        Document doc = new Document(request.title(), request.content(), principal.getUsername());
        Document saved = documentService.create(doc);
        return ResponseEntity.status(HttpStatus.CREATED).body(DocumentResponse.from(saved));
    }

    /**
     * PUT /api/documents/{id}
     * @PreAuthorize in the service delegates to @documentSecurity.isOwner — only the
     * owner or ADMIN may update.
     */
    @PutMapping("/{id}")
    public DocumentResponse updateDocument(@PathVariable Long id,
                                           @RequestBody UpdateDocumentRequest request) {
        return DocumentResponse.from(documentService.update(id, request.title(), request.content()));
    }

    /**
     * DELETE /api/documents/{id}
     * @PreAuthorize("hasRole('ADMIN')") in the service; any non-admin receives 403.
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteDocument(@PathVariable Long id) {
        documentService.delete(id);
        return ResponseEntity.noContent().build();
    }

    // --- DTOs ---

    public record DocumentResponse(Long id, String title, String content, String owner) {
        static DocumentResponse from(Document doc) {
            return new DocumentResponse(doc.getId(), doc.getTitle(), doc.getContent(), doc.getOwner());
        }
    }

    public record CreateDocumentRequest(String title, String content) {}

    public record UpdateDocumentRequest(String title, String content) {}
}
