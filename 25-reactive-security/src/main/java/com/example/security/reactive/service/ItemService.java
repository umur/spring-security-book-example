package com.example.security.reactive.service;

import com.example.security.reactive.model.Item;
import com.example.security.reactive.repository.ItemRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class ItemService {

    private final ItemRepository itemRepository;

    public Flux<Item> findAll() {
        return itemRepository.findAll();
    }

    public Mono<Item> findById(Long id) {
        return itemRepository.findById(id);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public Mono<Item> create(Item item) {
        return itemRepository.save(item);
    }
}
