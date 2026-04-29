package com.example.security.oauth2login.dto;

public record DashboardInfo(String name, String email, String picture, String provider) {

    public static DashboardInfo unknown() {
        return new DashboardInfo("", "", "", "unknown");
    }
}
