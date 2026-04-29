package com.example.security.acl.dto;

import com.example.security.acl.model.Document;

public record DocumentResponse(Long id, String title, String content, String owner) {

    public static DocumentResponse from(Document doc) {
        return new DocumentResponse(doc.getId(), doc.getTitle(), doc.getContent(), doc.getOwner());
    }
}
