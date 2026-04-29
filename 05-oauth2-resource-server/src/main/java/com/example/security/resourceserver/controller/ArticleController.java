package com.example.security.resourceserver.controller;

import com.example.security.resourceserver.model.Article;
import com.example.security.resourceserver.service.ArticleService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/articles")
@RequiredArgsConstructor
public class ArticleController {

    private final ArticleService articleService;

    public record ArticleRequest(
            @NotBlank String title,
            @NotBlank String content
    ) {}

    public record ArticleResponse(Long id, String title, String content, String authorUsername) {
        public static ArticleResponse from(Article article) {
            return new ArticleResponse(
                    article.getId(),
                    article.getTitle(),
                    article.getContent(),
                    article.getAuthorUsername()
            );
        }
    }

    @GetMapping
    public ResponseEntity<List<ArticleResponse>> listArticles() {
        return ResponseEntity.ok(articleService.findAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<ArticleResponse> getArticle(@PathVariable Long id) {
        return ResponseEntity.ok(articleService.findById(id));
    }

    @PostMapping
    public ResponseEntity<ArticleResponse> createArticle(
            @Valid @RequestBody ArticleRequest request,
            @AuthenticationPrincipal Jwt jwt) {
        String username = jwt.getSubject();
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(articleService.create(request, username));
    }
}
