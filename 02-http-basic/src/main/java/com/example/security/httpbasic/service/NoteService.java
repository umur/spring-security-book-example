package com.example.security.httpbasic.service;

import com.example.security.httpbasic.dto.NoteRequest;
import com.example.security.httpbasic.dto.NoteResponse;
import com.example.security.httpbasic.exception.NoteNotFoundException;
import com.example.security.httpbasic.model.Note;
import com.example.security.httpbasic.repository.NoteRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class NoteService {

    private final NoteRepository noteRepository;

    public List<NoteResponse> listAllNotes() {
        return noteRepository.findAll().stream()
                .map(this::toResponse)
                .toList();
    }

    public NoteResponse getNote(Long id) {
        return noteRepository.findById(id)
                .map(this::toResponse)
                .orElseThrow(() -> new NoteNotFoundException(id));
    }

    public NoteResponse createNote(NoteRequest request, String ownerUsername) {
        Note note = new Note(request.title(), request.content(), ownerUsername);
        return toResponse(noteRepository.save(note));
    }

    public NoteResponse updateNote(Long id, NoteRequest request) {
        Note note = noteRepository.findById(id)
                .orElseThrow(() -> new NoteNotFoundException(id));
        note.setTitle(request.title());
        note.setContent(request.content());
        return toResponse(noteRepository.save(note));
    }

    public void deleteNote(Long id) {
        if (!noteRepository.existsById(id)) {
            throw new NoteNotFoundException(id);
        }
        noteRepository.deleteById(id);
    }

    private NoteResponse toResponse(Note note) {
        return new NoteResponse(note.getId(), note.getTitle(), note.getContent(), note.getOwnerUsername());
    }
}
