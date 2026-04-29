package com.example.security.methodsecurity.repository;

import com.example.security.methodsecurity.model.Document;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface DocumentRepository extends JpaRepository<Document, Long> {
    List<Document> findByOwner(String owner);
}
