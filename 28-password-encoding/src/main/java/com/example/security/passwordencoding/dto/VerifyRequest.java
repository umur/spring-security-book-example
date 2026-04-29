package com.example.security.passwordencoding.dto;

public record VerifyRequest(String raw, String encoded, String algorithm) {}
