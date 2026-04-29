package com.example.security.websocket.repository;

import com.example.security.websocket.model.ChatMessage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ChatMessageRepository extends JpaRepository<ChatMessage, Long> {

    List<ChatMessage> findTop50ByOrderBySentAtDesc();

    List<ChatMessage> findByDestinationOrderBySentAtDesc(String destination);
}
