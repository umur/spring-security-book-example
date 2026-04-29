package com.example.security.saml2.service;

import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * Extracts user information from a SAML 2.0 assertion after successful authentication.
 *
 * Spring Security populates a {@link Saml2AuthenticatedPrincipal} with all attributes
 * asserted by the IdP. This service provides a clean API for the web layer to consume
 * those attributes without coupling the controller to the SAML API.
 */
@Service
public class Saml2UserService {

    /**
     * Returns the primary name identifier from the SAML assertion (NameID).
     */
    public String getNameId(Saml2AuthenticatedPrincipal principal) {
        return principal.getName();
    }

    /**
     * Returns the first value of the named SAML attribute, or {@code null} if absent.
     */
    public String getAttribute(Saml2AuthenticatedPrincipal principal, String attributeName) {
        List<Object> values = principal.getAttribute(attributeName);
        if (values == null || values.isEmpty()) {
            return null;
        }
        return String.valueOf(values.getFirst());
    }

    /**
     * Returns all SAML attributes asserted by the IdP as a flat string-keyed map.
     * Each entry holds the first value of that attribute for display purposes.
     */
    public Map<String, String> getAllAttributes(Saml2AuthenticatedPrincipal principal) {
        Map<String, List<Object>> raw = principal.getAttributes();
        Map<String, String> result = new java.util.LinkedHashMap<>();
        raw.forEach((key, values) -> {
            if (values != null && !values.isEmpty()) {
                result.put(key, String.valueOf(values.getFirst()));
            }
        });
        return result;
    }

    /**
     * Derives a display name for the authenticated user by trying common SAML
     * attribute names in order of preference, falling back to the NameID.
     */
    public String getDisplayName(Saml2AuthenticatedPrincipal principal) {
        for (String attr : List.of(
                "displayName",
                "urn:oid:2.16.840.1.113730.3.1.241",
                "cn",
                "urn:oid:2.5.4.3",
                "givenName",
                "urn:oid:2.5.4.42")) {
            String value = getAttribute(principal, attr);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return principal.getName();
    }

    /**
     * Extracts the email address from common SAML attribute names.
     */
    public String getEmail(Saml2AuthenticatedPrincipal principal) {
        for (String attr : List.of(
                "email",
                "mail",
                "urn:oid:0.9.2342.19200300.100.1.3",
                "emailAddress")) {
            String value = getAttribute(principal, attr);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }
}
