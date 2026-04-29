package com.example.security.saml2.controller;

import com.example.security.saml2.service.Saml2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Protected resource controller — only reachable after successful SAML 2.0 SSO.
 *
 * The controller is intentionally thin: all attribute extraction logic lives in
 * {@link Saml2UserService} so it is independently testable and decoupled from the
 * web layer.
 */
@RestController
@RequiredArgsConstructor
public class DashboardController {

    private final Saml2UserService saml2UserService;

    /**
     * GET /dashboard — returns SAML user attributes as JSON.
     *
     * Spring Security injects the authenticated {@link Saml2AuthenticatedPrincipal}
     * via {@code @AuthenticationPrincipal}. This works both with a real SAML assertion
     * and with the {@code .with(saml2Login())} test post-processor.
     */
    @GetMapping("/dashboard")
    public ResponseEntity<DashboardResponse> dashboard(
            @AuthenticationPrincipal Saml2AuthenticatedPrincipal principal) {

        DashboardResponse response = new DashboardResponse(
                saml2UserService.getNameId(principal),
                saml2UserService.getDisplayName(principal),
                saml2UserService.getEmail(principal),
                saml2UserService.getAllAttributes(principal)
        );
        return ResponseEntity.ok(response);
    }

    // --- DTOs ---

    public record DashboardResponse(
            String nameId,
            String displayName,
            String email,
            Map<String, String> attributes
    ) {}
}
