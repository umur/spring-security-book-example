package com.example.security.websocket.controller;

import com.example.security.websocket.model.ChatMessage;
import com.example.security.websocket.service.ChatService;
import lombok.RequiredArgsConstructor;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.stereotype.Controller;

import java.security.Principal;

@Controller
@RequiredArgsConstructor
public class ChatStompController {

    private final ChatService chatService;

    @MessageMapping("/chat.send")
    @SendTo("/topic/public")
    public ChatMessage sendMessage(ChatMessagePayload payload, Principal principal) {
        return chatService.saveMessage(principal.getName(), payload.getContent(), "/topic/public");
    }
}
