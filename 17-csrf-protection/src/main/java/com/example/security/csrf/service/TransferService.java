package com.example.security.csrf.service;

import com.example.security.csrf.dto.CsrfTokenResponse;
import com.example.security.csrf.dto.TransferResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Service;

@Service
public class TransferService {

    public String getUsername(UserDetails principal) {
        return principal.getUsername();
    }

    public String buildTransferMessage(String amount, String toAccount) {
        return "Transfer of " + amount + " to " + toAccount + " completed successfully.";
    }

    public TransferResponse buildApiTransferResponse(UserDetails principal, String toAccount, String amount) {
        return new TransferResponse(
                "success",
                principal.getUsername(),
                toAccount != null ? toAccount : "",
                amount != null ? amount : ""
        );
    }

    public CsrfTokenResponse buildCsrfTokenResponse(HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (token == null) {
            return new CsrfTokenResponse(null, null, null);
        }
        return new CsrfTokenResponse(token.getHeaderName(), token.getParameterName(), token.getToken());
    }
}
