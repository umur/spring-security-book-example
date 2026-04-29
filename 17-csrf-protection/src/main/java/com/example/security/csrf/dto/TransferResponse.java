package com.example.security.csrf.dto;

public record TransferResponse(
        String status,
        String user,
        String toAccount,
        String amount
) {
}
