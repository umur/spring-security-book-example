package com.example.security.jwt.repository;

import com.example.security.jwt.model.Task;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TaskRepository extends JpaRepository<Task, Long> {
    List<Task> findByOwnerUsername(String ownerUsername);
}
