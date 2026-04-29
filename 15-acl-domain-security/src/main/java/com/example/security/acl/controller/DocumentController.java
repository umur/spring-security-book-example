package com.example.security.acl.controller;

import com.example.security.acl.dto.DocumentResponse;
import com.example.security.acl.service.DocumentService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Thin controller — all business logic and security enforcement lives in DocumentService.
 */
@RestController
@RequestMapping("/api/documents")
@RequiredArgsConstructor
public class DocumentController {

    private final DocumentService documentService;

    @GetMapping
    public List<DocumentResponse> listDocuments() {
        return documentService.getReadableDocuments();
    }

    @GetMapping("/{id}")
    public DocumentResponse getDocument(@PathVariable Long id) {
        return documentService.getDocumentResponse(id);
    }

    @PostMapping
    public ResponseEntity<DocumentResponse> createDocument(@RequestBody CreateDocumentRequest request,
                                                            @AuthenticationPrincipal UserDetails principal) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(documentService.create(request.title(), request.content(), principal.getUsername()));
    }

    @PutMapping("/{id}/permissions")
    public ResponseEntity<Void> grantPermission(@PathVariable Long id,
                                                 @RequestBody GrantPermissionRequest request) {
        documentService.grantPermission(id, request.username(), request.permission());
        return ResponseEntity.ok().build();
    }

    // -----------------------------------------------------------------------
    // DTOs
    // -----------------------------------------------------------------------

    public record CreateDocumentRequest(String title, String content) {}

    public record GrantPermissionRequest(String username, String permission) {}
}
