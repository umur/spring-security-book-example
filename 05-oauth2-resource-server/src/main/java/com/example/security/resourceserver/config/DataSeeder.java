package com.example.security.resourceserver.config;

import com.example.security.resourceserver.model.Article;
import com.example.security.resourceserver.repository.ArticleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataSeeder implements ApplicationRunner {

    private final ArticleRepository articleRepository;

    @Override
    public void run(ApplicationArguments args) {
        if (articleRepository.count() == 0) {
            articleRepository.save(new Article(
                    "Spring Security Resource Server",
                    "A comprehensive guide to protecting REST APIs with JWT.",
                    "system"));
            articleRepository.save(new Article(
                    "OAuth2 Scopes and Roles",
                    "How scopes and roles work together in a resource server.",
                    "system"));
        }
    }
}
