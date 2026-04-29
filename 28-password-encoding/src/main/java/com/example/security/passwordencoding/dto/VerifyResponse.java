package com.example.security.passwordencoding.dto;

public record VerifyResponse(String algorithm, boolean matches) {}
