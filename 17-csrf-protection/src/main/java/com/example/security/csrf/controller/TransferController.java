package com.example.security.csrf.controller;

import com.example.security.csrf.dto.CsrfTokenResponse;
import com.example.security.csrf.dto.TransferResponse;
import com.example.security.csrf.service.TransferService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Demonstrates CSRF protection for two patterns:
 *
 * <ul>
 *   <li>Form-based (Thymeleaf): POST /transfer — session-based CSRF token injected by th:action</li>
 *   <li>SPA/API: POST /api/transfer — cookie-based CSRF via CookieCsrfTokenRepository</li>
 * </ul>
 */
@Controller
public class TransferController {

    private final TransferService transferService;

    public TransferController(TransferService transferService) {
        this.transferService = transferService;
    }

    /**
     * GET /transfer — renders the Thymeleaf form. Thymeleaf's th:action automatically
     * adds the hidden _csrf field using the session-stored token.
     */
    @GetMapping("/transfer")
    public String transferForm(Model model,
                               @AuthenticationPrincipal UserDetails principal) {
        model.addAttribute("username", transferService.getUsername(principal));
        return "transfer";
    }

    /**
     * POST /transfer — form submission protected by session-based CSRF token.
     * Spring Security validates the token before this handler is reached.
     * Returns 403 if the CSRF token is missing or invalid.
     */
    @PostMapping("/transfer")
    public String processTransfer(@RequestParam String toAccount,
                                  @RequestParam String amount,
                                  Model model,
                                  @AuthenticationPrincipal UserDetails principal) {
        model.addAttribute("username", transferService.getUsername(principal));
        model.addAttribute("message", transferService.buildTransferMessage(amount, toAccount));
        return "transfer";
    }

    /**
     * POST /api/transfer — SPA-style endpoint protected by cookie-based CSRF token.
     * The client must read the XSRF-TOKEN cookie and send its value in the
     * X-XSRF-TOKEN request header (or _csrf parameter).
     */
    @PostMapping("/api/transfer")
    @ResponseBody
    public ResponseEntity<TransferResponse> apiTransfer(
            @RequestParam(required = false) String toAccount,
            @RequestParam(required = false) String amount,
            @AuthenticationPrincipal UserDetails principal) {
        return ResponseEntity.ok(transferService.buildApiTransferResponse(principal, toAccount, amount));
    }

    /**
     * GET /csrf-token — convenience endpoint for SPAs to fetch the current CSRF token.
     * The CookieCsrfTokenRepository also sets the XSRF-TOKEN cookie on every response,
     * so SPAs can read it directly; this endpoint makes it explicit and testable.
     */
    @GetMapping("/csrf-token")
    @ResponseBody
    public ResponseEntity<CsrfTokenResponse> getCsrfToken(HttpServletRequest request) {
        return ResponseEntity.ok(transferService.buildCsrfTokenResponse(request));
    }
}
