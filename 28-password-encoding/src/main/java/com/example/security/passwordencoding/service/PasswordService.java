package com.example.security.passwordencoding.service;

import com.example.security.passwordencoding.dto.EncodeResponse;
import com.example.security.passwordencoding.dto.PasswordInfoResponse;
import com.example.security.passwordencoding.dto.VerifyRequest;
import com.example.security.passwordencoding.dto.VerifyResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * Encapsulates all password encoding and verification logic.
 *
 * <p>Algorithm selection, map-building, info generation, and example hash
 * creation all live here — keeping the controller free of any logic.</p>
 */
@Service
@RequiredArgsConstructor
public class PasswordService {

    private final PasswordEncoder delegatingPasswordEncoder;
    private final BCryptPasswordEncoder bcryptPasswordEncoder;
    private final Argon2PasswordEncoder argon2PasswordEncoder;
    private final Pbkdf2PasswordEncoder pbkdf2PasswordEncoder;
    private final SCryptPasswordEncoder scryptPasswordEncoder;

    public EncodeResponse encode(String raw, String algorithm) {
        String normalised = algorithm.toLowerCase();
        String encoded = switch (normalised) {
            case "argon2"     -> argon2PasswordEncoder.encode(raw);
            case "pbkdf2"     -> pbkdf2PasswordEncoder.encode(raw);
            case "scrypt"     -> scryptPasswordEncoder.encode(raw);
            case "delegating" -> delegatingPasswordEncoder.encode(raw);
            default           -> bcryptPasswordEncoder.encode(raw);
        };
        return new EncodeResponse(normalised, raw, encoded);
    }

    public VerifyResponse verify(VerifyRequest request) {
        String algorithm = request.algorithm() != null ? request.algorithm() : "delegating";
        String normalised = algorithm.toLowerCase();
        boolean matches = switch (normalised) {
            case "bcrypt"  -> bcryptPasswordEncoder.matches(request.raw(), request.encoded());
            case "argon2"  -> argon2PasswordEncoder.matches(request.raw(), request.encoded());
            case "pbkdf2"  -> pbkdf2PasswordEncoder.matches(request.raw(), request.encoded());
            case "scrypt"  -> scryptPasswordEncoder.matches(request.raw(), request.encoded());
            default        -> delegatingPasswordEncoder.matches(request.raw(), request.encoded());
        };
        return new VerifyResponse(normalised, matches);
    }

    public PasswordInfoResponse info() {
        String exampleRaw = "demonstration";
        String bcryptHash = bcryptPasswordEncoder.encode(exampleRaw);
        String delegatingHash = delegatingPasswordEncoder.encode(exampleRaw);

        return new PasswordInfoResponse(
                "DelegatingPasswordEncoder stores a {id} prefix with each hash. " +
                "On verification it reads the prefix, selects the matching encoder, " +
                "and delegates matches(). This allows you to change the default algorithm " +
                "without invalidating existing hashes — old hashes keep working while new " +
                "registrations use the current default.",
                "bcrypt",
                Map.of(
                        "bcrypt",     "Adaptive hash — work factor controlled by strength parameter",
                        "argon2",     "Memory-hard algorithm resistant to GPU attacks (winner of PHC 2015)",
                        "pbkdf2",     "NIST-recommended key derivation, FIPS-compliant",
                        "scrypt",     "Memory-hard, sequential-memory-hard, resistant to ASICs",
                        "delegating", "Wraps all of the above; reads {prefix} to select encoder at verify time"
                ),
                List.of(
                        "1. Change encodingId in DelegatingPasswordEncoder to the new algorithm",
                        "2. New user registrations are stored with the new {prefix}",
                        "3. Existing {old-prefix} hashes continue to verify correctly",
                        "4. Optionally, re-hash on next successful login using UserDetailsPasswordService"
                ),
                bcryptHash,
                delegatingHash,
                delegatingPasswordEncoder.matches(exampleRaw, delegatingHash)
        );
    }
}
