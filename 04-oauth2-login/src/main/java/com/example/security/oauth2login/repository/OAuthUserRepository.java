package com.example.security.oauth2login.repository;

import com.example.security.oauth2login.model.OAuthUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OAuthUserRepository extends JpaRepository<OAuthUser, Long> {

    Optional<OAuthUser> findByProviderAndProviderId(String provider, String providerId);
}
