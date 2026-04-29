package com.example.security.jwt.dto;

import com.example.security.jwt.model.Task;

public record TaskResponse(Long id, String title, String description, String ownerUsername) {
    public static TaskResponse from(Task task) {
        return new TaskResponse(task.getId(), task.getTitle(), task.getDescription(), task.getOwnerUsername());
    }
}
