package com.example.security.passwordencoding.dto;

public record EncodeResponse(String algorithm, String raw, String encoded) {}
