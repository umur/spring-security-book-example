package com.example.security.customprovider.repository;

import com.example.security.customprovider.model.DomainToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface DomainTokenRepository extends JpaRepository<DomainToken, Long> {

    Optional<DomainToken> findByTokenValue(String tokenValue);
}
