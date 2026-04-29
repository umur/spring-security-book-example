package com.example.security.microservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.external-service")
public record ExternalServiceProperties(
        String baseUrl,
        String dataPath
) {}
