package com.example.security.httpbasic.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(NoteNotFoundException.class)
    public ResponseEntity<Void> handleNoteNotFound(NoteNotFoundException ex) {
        return ResponseEntity.notFound().build();
    }
}
