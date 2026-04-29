package com.example.security.jwt;

import com.example.security.jwt.config.JwtProperties;
import com.example.security.jwt.service.JwtService;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private JwtService jwtService;
    private UserDetails userDetails;

    @BeforeEach
    void setUp() {
        // 64-char hex string → 32 bytes → valid 256-bit HMAC-SHA key
        JwtProperties props = new JwtProperties(
                "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970",
                900_000L,
                604_800_000L
        );
        jwtService = new JwtService(props);
        userDetails = new User("testuser", "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Nested
    @DisplayName("Token generation")
    class TokenGeneration {

        @Test
        @DisplayName("generateAccessToken produces a non-blank token")
        void generateAccessTokenProducesToken() {
            String token = jwtService.generateAccessToken(userDetails);
            assertThat(token).isNotBlank();
        }

        @Test
        @DisplayName("Generated access token contains expected username claim")
        void generatedTokenContainsUsername() {
            String token = jwtService.generateAccessToken(userDetails);
            assertThat(jwtService.extractUsername(token)).isEqualTo("testuser");
        }

        @Test
        @DisplayName("Generated access token contains roles claim")
        void generatedTokenContainsRoles() {
            String token = jwtService.generateAccessToken(userDetails);
            List<String> roles = jwtService.extractRoles(token);
            assertThat(roles).containsExactly("ROLE_USER");
        }

        @Test
        @DisplayName("Refresh token contains username but no roles")
        void refreshTokenContainsUsernameButNoRoles() {
            String token = jwtService.generateRefreshToken(userDetails);
            assertThat(jwtService.extractUsername(token)).isEqualTo("testuser");
            assertThat(jwtService.extractRoles(token)).isEmpty();
        }
    }

    @Nested
    @DisplayName("Token validation")
    class TokenValidation {

        @Test
        @DisplayName("Valid token passes validation against correct user")
        void validTokenPassesValidation() {
            String token = jwtService.generateAccessToken(userDetails);
            assertThat(jwtService.isTokenValid(token, userDetails)).isTrue();
        }

        @Test
        @DisplayName("Valid token passes single-arg validation")
        void validTokenPassesSingleArgValidation() {
            String token = jwtService.generateAccessToken(userDetails);
            assertThat(jwtService.isTokenValid(token)).isTrue();
        }

        @Test
        @DisplayName("Token for different user fails validation")
        void tokenForDifferentUserFailsValidation() {
            String token = jwtService.generateAccessToken(userDetails);
            UserDetails otherUser = new User("otheruser", "password",
                    List.of(new SimpleGrantedAuthority("ROLE_USER")));
            assertThat(jwtService.isTokenValid(token, otherUser)).isFalse();
        }

        @Test
        @DisplayName("Malformed token fails single-arg validation")
        void malformedTokenFailsValidation() {
            assertThat(jwtService.isTokenValid("not.a.valid.jwt.token")).isFalse();
        }

        @Test
        @DisplayName("Expired token throws exception on claim extraction")
        void expiredTokenThrowsOnExtraction() {
            JwtProperties shortLivedProps = new JwtProperties(
                    "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970",
                    -1000L,  // already expired
                    604_800_000L
            );
            JwtService shortLivedService = new JwtService(shortLivedProps);
            String expiredToken = shortLivedService.generateAccessToken(userDetails);

            assertThatThrownBy(() -> shortLivedService.isTokenValid(expiredToken, userDetails))
                    .isInstanceOf(JwtException.class);
        }

        @Test
        @DisplayName("Expired token fails single-arg validation")
        void expiredTokenFailsSingleArgValidation() {
            JwtProperties shortLivedProps = new JwtProperties(
                    "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970",
                    -1000L,
                    604_800_000L
            );
            JwtService shortLivedService = new JwtService(shortLivedProps);
            String expiredToken = shortLivedService.generateAccessToken(userDetails);
            assertThat(shortLivedService.isTokenValid(expiredToken)).isFalse();
        }
    }

    @Nested
    @DisplayName("Username extraction")
    class UsernameExtraction {

        @Test
        @DisplayName("extractUsername returns correct username from access token")
        void extractUsernameFromAccessToken() {
            String token = jwtService.generateAccessToken(userDetails);
            assertThat(jwtService.extractUsername(token)).isEqualTo("testuser");
        }

        @Test
        @DisplayName("extractUsername returns correct username from refresh token")
        void extractUsernameFromRefreshToken() {
            String token = jwtService.generateRefreshToken(userDetails);
            assertThat(jwtService.extractUsername(token)).isEqualTo("testuser");
        }

        @Test
        @DisplayName("extractUsername throws on malformed token")
        void extractUsernameThrowsOnMalformedToken() {
            assertThatThrownBy(() -> jwtService.extractUsername("bad.token.here"))
                    .isInstanceOf(JwtException.class);
        }
    }
}
