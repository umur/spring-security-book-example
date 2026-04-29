package com.example.security.auditing.repository;

import com.example.security.auditing.model.AuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    List<AuditEvent> findTop50ByOrderByTimestampDesc();

    List<AuditEvent> findByUsernameOrderByTimestampDesc(String username);
}
