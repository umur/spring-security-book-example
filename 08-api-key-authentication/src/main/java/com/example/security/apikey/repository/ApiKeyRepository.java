package com.example.security.apikey.repository;

import com.example.security.apikey.model.ApiKey;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ApiKeyRepository extends JpaRepository<ApiKey, Long> {

    List<ApiKey> findAllByActiveTrue();
}
