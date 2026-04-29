package com.example.security.acl.service;

import com.example.security.acl.dto.DocumentResponse;
import com.example.security.acl.model.Document;
import com.example.security.acl.repository.DocumentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Manages Document CRUD and ACL permission grants.
 *
 * ACL permissions used:
 *   READ  (1) — read the document
 *   WRITE (2) — update the document
 *   DELETE (8) — delete the document
 *   ADMINISTRATION (16) — grant/revoke other users' permissions
 *
 * The owner is granted all four permissions upon document creation.
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class DocumentService {

    private final DocumentRepository documentRepository;
    private final MutableAclService aclService;

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /**
     * Returns the document as a response DTO, enforcing READ permission via ACL.
     * Uses id-based hasPermission so the check works against the Document ACL entry
     * even though the return type is DocumentResponse.
     */
    @PreAuthorize("hasRole('ADMIN') or hasPermission(#id, 'com.example.security.acl.model.Document', 'READ')")
    public DocumentResponse getDocumentResponse(Long id) {
        return DocumentResponse.from(
                documentRepository.findById(id)
                        .orElseThrow(() -> new DocumentNotFoundException(id)));
    }

    /**
     * Loads a Document entity by id with ACL READ enforcement.
     * Used internally by other service methods that need the entity.
     */
    @PostAuthorize("hasRole('ADMIN') or hasPermission(returnObject, 'READ')")
    public Document findById(Long id) {
        return documentRepository.findById(id)
                .orElseThrow(() -> new DocumentNotFoundException(id));
    }

    /**
     * Returns all documents; callers must filter by checking ACL individually.
     * The controller is responsible for only returning documents the user can see.
     */
    public List<Document> findAll() {
        return documentRepository.findAll();
    }

    /**
     * Returns only the documents the current principal is allowed to read,
     * already mapped to response DTOs.
     * ADMIN sees every document; regular users see only documents for which they
     * hold at least READ permission (checked via ACL).
     */
    public List<DocumentResponse> getReadableDocuments() {
        return documentRepository.findAll().stream()
                .filter(this::canRead)
                .map(DocumentResponse::from)
                .toList();
    }

    /**
     * Checks whether the current principal has READ permission on the given document.
     */
    public boolean canRead(Document document) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) return false;
        boolean isAdmin = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        if (isAdmin) return true;
        try {
            ObjectIdentity oi = new ObjectIdentityImpl(Document.class, document.getId());
            Acl acl = aclService.readAclById(oi);
            return acl.isGranted(
                    List.of(BasePermission.READ),
                    List.of(new PrincipalSid(auth.getName())),
                    false);
        } catch (NotFoundException e) {
            return false;
        }
    }

    // -----------------------------------------------------------------------
    // Mutations
    // -----------------------------------------------------------------------

    /**
     * Creates a document and grants full ACL permissions (READ, WRITE, DELETE,
     * ADMINISTRATION) to the owner principal so they can manage the document.
     */
    @Transactional
    public DocumentResponse create(String title, String content, String owner) {
        Document saved = documentRepository.save(new Document(title, content, owner));
        grantFullPermissions(saved, owner);
        return DocumentResponse.from(saved);
    }

    /**
     * Updates a document's title and content.
     * Caller must hold WRITE permission (enforced by @PreAuthorize).
     */
    @PreAuthorize("hasRole('ADMIN') or hasPermission(#id, 'com.example.security.acl.model.Document', 'WRITE')")
    @Transactional
    public Document update(Long id, String title, String content) {
        Document doc = documentRepository.findById(id)
                .orElseThrow(() -> new DocumentNotFoundException(id));
        doc.setTitle(title);
        doc.setContent(content);
        return documentRepository.save(doc);
    }

    /**
     * Deletes a document and removes its ACL entries.
     * Caller must hold DELETE permission (enforced by @PreAuthorize).
     */
    @PreAuthorize("hasRole('ADMIN') or hasPermission(#id, 'com.example.security.acl.model.Document', 'DELETE')")
    @Transactional
    public void delete(Long id) {
        if (!documentRepository.existsById(id)) {
            throw new DocumentNotFoundException(id);
        }
        documentRepository.deleteById(id);
        // Remove ACL entries for the deleted object
        ObjectIdentity oi = new ObjectIdentityImpl(Document.class, id);
        aclService.deleteAcl(oi, true);
    }

    /**
     * Grants a specific permission to a target user on a document.
     * Caller must hold ADMINISTRATION permission (enforced by @PreAuthorize).
     *
     * @param documentId the document to grant permission on
     * @param targetUsername the user to receive the permission
     * @param permissionName READ | WRITE | DELETE | ADMINISTRATION
     */
    @PreAuthorize("hasRole('ADMIN') or hasPermission(#documentId, 'com.example.security.acl.model.Document', 'ADMINISTRATION')")
    @Transactional
    public void grantPermission(Long documentId, String targetUsername, String permissionName) {
        if (!documentRepository.existsById(documentId)) {
            throw new DocumentNotFoundException(documentId);
        }
        Permission permission = resolvePermission(permissionName);
        ObjectIdentity oi = new ObjectIdentityImpl(Document.class, documentId);
        MutableAcl acl = loadOrCreateAcl(oi);
        acl.insertAce(acl.getEntries().size(), permission, new PrincipalSid(targetUsername), true);
        aclService.updateAcl(acl);
    }

    /**
     * Revokes a specific permission from a target user on a document.
     * Caller must hold ADMINISTRATION permission.
     */
    @PreAuthorize("hasRole('ADMIN') or hasPermission(#documentId, 'com.example.security.acl.model.Document', 'ADMINISTRATION')")
    @Transactional
    public void revokePermission(Long documentId, String targetUsername, String permissionName) {
        if (!documentRepository.existsById(documentId)) {
            throw new DocumentNotFoundException(documentId);
        }
        Permission permission = resolvePermission(permissionName);
        ObjectIdentity oi = new ObjectIdentityImpl(Document.class, documentId);
        MutableAcl acl;
        try {
            acl = (MutableAcl) aclService.readAclById(oi);
        } catch (NotFoundException e) {
            return;
        }
        PrincipalSid sid = new PrincipalSid(targetUsername);
        List<AccessControlEntry> entries = acl.getEntries();
        for (int i = entries.size() - 1; i >= 0; i--) {
            AccessControlEntry entry = entries.get(i);
            if (entry.getSid().equals(sid) && entry.getPermission().equals(permission)) {
                acl.deleteAce(i);
            }
        }
        aclService.updateAcl(acl);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    private void grantFullPermissions(Document document, String username) {
        ObjectIdentity oi = new ObjectIdentityImpl(Document.class, document.getId());
        MutableAcl acl = aclService.createAcl(oi);
        PrincipalSid sid = new PrincipalSid(username);
        acl.insertAce(0, BasePermission.READ,           sid, true);
        acl.insertAce(1, BasePermission.WRITE,          sid, true);
        acl.insertAce(2, BasePermission.DELETE,         sid, true);
        acl.insertAce(3, BasePermission.ADMINISTRATION, sid, true);
        aclService.updateAcl(acl);
    }

    private MutableAcl loadOrCreateAcl(ObjectIdentity oi) {
        try {
            return (MutableAcl) aclService.readAclById(oi);
        } catch (NotFoundException e) {
            return aclService.createAcl(oi);
        }
    }

    private Permission resolvePermission(String name) {
        return switch (name.toUpperCase()) {
            case "READ"           -> BasePermission.READ;
            case "WRITE"          -> BasePermission.WRITE;
            case "DELETE"         -> BasePermission.DELETE;
            case "ADMINISTRATION" -> BasePermission.ADMINISTRATION;
            default -> throw new IllegalArgumentException("Unknown permission: " + name);
        };
    }

    // -----------------------------------------------------------------------
    // Exception
    // -----------------------------------------------------------------------

    public static class DocumentNotFoundException extends RuntimeException {
        public DocumentNotFoundException(Long id) {
            super("Document not found: " + id);
        }
    }
}
