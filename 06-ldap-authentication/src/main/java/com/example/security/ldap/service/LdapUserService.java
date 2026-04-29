package com.example.security.ldap.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class LdapUserService {

    public record UserProfile(String username, String dn, List<String> roles) {}

    public UserProfile getProfile(Authentication authentication) {
        String username = authentication.getName();
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        String dn = "";
        if (authentication.getPrincipal() instanceof LdapUserDetails ldapUser) {
            dn = ldapUser.getDn();
        }

        return new UserProfile(username, dn, roles);
    }
}
