package com.example.security.apikey.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "api_keys")
@Getter
@Setter
@NoArgsConstructor
public class ApiKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String keyHash;

    @Column(nullable = false)
    private String owner;

    @Column(nullable = false)
    private String roles;

    @Column(nullable = false)
    private boolean active = true;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    public ApiKey(String keyHash, String owner, String roles) {
        this.keyHash = keyHash;
        this.owner = owner;
        this.roles = roles;
    }
}
