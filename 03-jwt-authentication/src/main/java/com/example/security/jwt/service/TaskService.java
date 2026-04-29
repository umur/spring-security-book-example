package com.example.security.jwt.service;

import com.example.security.jwt.dto.TaskRequest;
import com.example.security.jwt.dto.TaskResponse;
import com.example.security.jwt.model.Task;
import com.example.security.jwt.repository.TaskRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class TaskService {

    private final TaskRepository taskRepository;

    public List<TaskResponse> listAllTasks() {
        return taskRepository.findAll().stream()
                .map(TaskResponse::from)
                .toList();
    }

    public TaskResponse createTask(TaskRequest request, String ownerUsername) {
        Task task = new Task(request.title(), request.description(), ownerUsername);
        Task saved = taskRepository.save(task);
        return TaskResponse.from(saved);
    }
}
