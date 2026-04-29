package com.example.security.resourceserver.service;

import com.example.security.resourceserver.controller.ArticleController.ArticleRequest;
import com.example.security.resourceserver.controller.ArticleController.ArticleResponse;
import com.example.security.resourceserver.model.Article;
import com.example.security.resourceserver.repository.ArticleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ArticleService {

    private final ArticleRepository articleRepository;

    @Transactional(readOnly = true)
    public List<ArticleResponse> findAll() {
        return articleRepository.findAll().stream()
                .map(ArticleResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public ArticleResponse findById(Long id) {
        return articleRepository.findById(id)
                .map(ArticleResponse::from)
                .orElseThrow(() -> new ArticleNotFoundException(id));
    }

    @Transactional
    public ArticleResponse create(ArticleRequest request, String authorUsername) {
        Article article = new Article(request.title(), request.content(), authorUsername);
        return ArticleResponse.from(articleRepository.save(article));
    }

    public static class ArticleNotFoundException extends RuntimeException {
        public ArticleNotFoundException(Long id) {
            super("Article not found: " + id);
        }
    }
}
