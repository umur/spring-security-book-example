package com.example.security.customprovider;

import com.example.security.customprovider.model.DomainToken;
import com.example.security.customprovider.repository.DomainTokenRepository;
import com.example.security.customprovider.security.DomainTokenAuthenticationProvider;
import com.example.security.customprovider.security.DomainTokenAuthenticationToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DomainTokenAuthenticationProviderTest {

    @Mock
    private DomainTokenRepository domainTokenRepository;

    @InjectMocks
    private DomainTokenAuthenticationProvider provider;

    @Nested
    @DisplayName("supports()")
    class Supports {

        @Test
        @DisplayName("returns true for DomainTokenAuthenticationToken")
        void supportsDomainTokenAuthenticationToken() {
            assertThat(provider.supports(DomainTokenAuthenticationToken.class)).isTrue();
        }

        @Test
        @DisplayName("returns false for UsernamePasswordAuthenticationToken")
        void doesNotSupportUsernamePasswordAuthenticationToken() {
            assertThat(provider.supports(UsernamePasswordAuthenticationToken.class)).isFalse();
        }
    }

    @Nested
    @DisplayName("authenticate()")
    class Authenticate {

        private static final String VALID_TOKEN = "dtkn-valid-token";
        private static final String INVALID_TOKEN = "dtkn-invalid-token";

        @Test
        @DisplayName("valid token returns authenticated Authentication with username and role")
        void validTokenAuthenticatesSuccessfully() {
            Instant now = Instant.now();
            var domainToken = new DomainToken(VALID_TOKEN, "tokenuser", "USER",
                    now, now.plus(1, ChronoUnit.HOURS));
            when(domainTokenRepository.findByTokenValue(VALID_TOKEN)).thenReturn(Optional.of(domainToken));

            Authentication result = provider.authenticate(new DomainTokenAuthenticationToken(VALID_TOKEN));

            assertThat(result.isAuthenticated()).isTrue();
            assertThat(result.getName()).isEqualTo("tokenuser");
            assertThat(result.getAuthorities())
                    .extracting(a -> a.getAuthority())
                    .containsExactly("ROLE_USER");
        }

        @Test
        @DisplayName("unknown token throws BadCredentialsException")
        void unknownTokenThrowsBadCredentials() {
            when(domainTokenRepository.findByTokenValue(INVALID_TOKEN)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> provider.authenticate(new DomainTokenAuthenticationToken(INVALID_TOKEN)))
                    .isInstanceOf(BadCredentialsException.class)
                    .hasMessageContaining("Invalid domain token");
        }

        @Test
        @DisplayName("expired token throws BadCredentialsException")
        void expiredTokenThrowsBadCredentials() {
            Instant past = Instant.now().minus(2, ChronoUnit.HOURS);
            var expiredToken = new DomainToken(VALID_TOKEN, "expireduser", "USER",
                    past.minus(1, ChronoUnit.HOURS), past);
            when(domainTokenRepository.findByTokenValue(VALID_TOKEN)).thenReturn(Optional.of(expiredToken));

            assertThatThrownBy(() -> provider.authenticate(new DomainTokenAuthenticationToken(VALID_TOKEN)))
                    .isInstanceOf(BadCredentialsException.class)
                    .hasMessageContaining("expired");
        }

        @Test
        @DisplayName("authenticated result has null credentials (erased)")
        void authenticatedTokenHasNullCredentials() {
            Instant now = Instant.now();
            var domainToken = new DomainToken(VALID_TOKEN, "tokenuser", "ADMIN",
                    now, now.plus(1, ChronoUnit.HOURS));
            when(domainTokenRepository.findByTokenValue(VALID_TOKEN)).thenReturn(Optional.of(domainToken));

            Authentication result = provider.authenticate(new DomainTokenAuthenticationToken(VALID_TOKEN));

            assertThat(result.getCredentials()).isNull();
        }
    }
}
