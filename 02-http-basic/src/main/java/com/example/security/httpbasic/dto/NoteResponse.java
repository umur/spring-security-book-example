package com.example.security.httpbasic.dto;

public record NoteResponse(Long id, String title, String content, String ownerUsername) {}
