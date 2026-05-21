package com.cinetrack.mfa;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * In-memory UserDetailsService backed by a fixed map of MfaUser records.
 *
 * alice has a TOTP secret and therefore must complete the second factor
 * before accessing endpoints that require FACTOR_TOTP authority.
 *
 * bob has no TOTP secret and can only reach endpoints protected by
 * FACTOR_PASSWORD.
 *
 * Note: passwords are stored with the {noop} prefix so that Spring Security's
 * DelegatingPasswordEncoder accepts them without a BCrypt round-trip in tests.
 */
@Service
public class MfaUserDetailsService implements UserDetailsService {

    static final String ALICE_TOTP_SECRET = "JBSWY3DPEHPK3PXP";

    private static final Map<String, MfaUser> USERS = Map.of(
            "alice", new MfaUser(
                    "alice",
                    "{noop}password",
                    ALICE_TOTP_SECRET,
                    java.util.Set.of("USER")
            ),
            "bob", new MfaUser(
                    "bob",
                    "{noop}password",
                    null,
                    java.util.Set.of("USER")
            )
    );

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        MfaUser mfaUser = USERS.get(username);
        if (mfaUser == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        List<SimpleGrantedAuthority> authorities = mfaUser.roles().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());

        return new User(mfaUser.username(), mfaUser.password(), authorities);
    }

    /**
     * Looks up the raw MfaUser record so that MfaController can retrieve the
     * TOTP secret without a second service call.
     */
    public MfaUser findMfaUser(String username) {
        MfaUser user = USERS.get(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }
        return user;
    }
}
