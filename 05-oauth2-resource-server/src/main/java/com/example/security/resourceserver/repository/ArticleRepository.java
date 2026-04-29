package com.example.security.resourceserver.repository;

import com.example.security.resourceserver.model.Article;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ArticleRepository extends JpaRepository<Article, Long> {
}
