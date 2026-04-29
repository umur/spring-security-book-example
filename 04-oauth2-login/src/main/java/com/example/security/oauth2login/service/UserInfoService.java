package com.example.security.oauth2login.service;

import com.example.security.oauth2login.dto.DashboardInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class UserInfoService {

    public DashboardInfo resolveDashboardInfo(Object principal) {
        if (principal instanceof OidcUser oidcUser) {
            return new DashboardInfo(
                    nullToEmpty(oidcUser.getFullName()),
                    nullToEmpty(oidcUser.getEmail()),
                    nullToEmpty(oidcUser.getPicture()),
                    "oidc"
            );
        }
        if (principal instanceof OAuth2User oauth2User) {
            return new DashboardInfo(
                    nullToEmpty(oauth2User.getAttribute("name")),
                    nullToEmpty(oauth2User.getAttribute("email")),
                    nullToEmpty(oauth2User.getAttribute("avatar_url")),
                    "oauth2"
            );
        }
        return DashboardInfo.unknown();
    }

    private String nullToEmpty(String value) {
        return value != null ? value : "";
    }
}
