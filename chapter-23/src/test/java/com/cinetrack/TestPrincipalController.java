package com.cinetrack;

import com.cinetrack.security.CineTrackPrincipal;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Test-only controller that returns the resolved {@link CineTrackPrincipal}
 * as JSON, used by {@link WithMockUserTest} to assert on the concrete
 * principal type injected via {@code @AuthenticationPrincipal}.
 */
@RestController
@RequestMapping("/api/test")
public class TestPrincipalController {

    @GetMapping("/principal")
    public CineTrackPrincipal principal(
            @AuthenticationPrincipal CineTrackPrincipal principal) {
        return principal;
    }
}
