package com.example.security.websocket.service;

import com.example.security.websocket.model.ChatMessage;
import com.example.security.websocket.repository.ChatMessageRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ChatService {

    private final ChatMessageRepository chatMessageRepository;

    @Transactional
    public ChatMessage saveMessage(String sender, String content, String destination) {
        ChatMessage message = ChatMessage.builder()
                .sender(sender)
                .content(content)
                .destination(destination)
                .sentAt(Instant.now())
                .build();
        return chatMessageRepository.save(message);
    }

    @Transactional(readOnly = true)
    public List<ChatMessage> getRecentMessages() {
        return chatMessageRepository.findTop50ByOrderBySentAtDesc();
    }

    @Transactional(readOnly = true)
    public List<ChatMessage> getMessagesByDestination(String destination) {
        return chatMessageRepository.findByDestinationOrderBySentAtDesc(destination);
    }
}
