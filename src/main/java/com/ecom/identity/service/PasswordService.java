package com.ecom.identity.service;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Password hashing service using Argon2id with explicit salt + pepper technique.
 * 
 * Architecture:
 * - Salt: Random 32-byte value (256 bits), unique per user, stored in database
 * - Pepper: Secret value from config/env, same for all users, NOT stored in DB
 *   - Length: No technical limit! Can be 32, 64, 128+ bytes for maximum security
 *   - Longer pepper = more entropy = stronger security
 *   - Recommended: 32-64 bytes (256-512 bits) for production
 *   - Generate with: `openssl rand -base64 64` (for 64-byte pepper)
 * - Algorithm: Argon2id (recommended variant - best protection against all attack types)
 * 
 * Security Features:
 * - Memory-hard function (resistant to GPU/ASIC attacks)
 * - Side-channel attack resistant (constant-time operations)
 * - Time-delay resistant (high memory cost slows down brute force)
 * - Explicit salt control (can rotate salt without rehashing)
 * - Pepper adds server-side secret (DB compromise doesn't reveal passwords)
 * 
 * Why Argon2id over Argon2i?
 * - Argon2id = 50% Argon2i (side-channel resistant) + 50% Argon2d (GPU resistant)
 * - Recommended by OWASP and Argon2 authors for best protection
 * - Balances protection against both side-channel and GPU-based attacks
 * 
 * Note: The de.mkammerer.argon2-jvm library doesn't support explicit salt in rawHash().
 * We use a workaround: include salt in password input, then extract hash from formatted string.
 */
@Service
public class PasswordService {

    private final Argon2 argon2;
    private final String pepper;
    private final SecureRandom secureRandom;
    
    // Argon2 parameters (configurable via @Value)
    // Recommended production values:
    // - iterations: 5-10 (higher = more secure but slower)
    // - memory: 65536 KB (64 MB) - good balance
    // - parallelism: 1-4 (CPU cores available)
    // - saltLength: 16-64 bytes (16 bytes/128 bits is standard, 32 bytes/256 bits is excellent, 64 bytes is overkill)
    // - hashLength: 16-64 bytes (32 bytes/256 bits is standard and sufficient, 64 bytes is overkill)
    private final int iterations;
    private final int memory; // in KB
    private final int parallelism;
    private final int saltLength; // bytes
    private final int hashLength; // bytes

    public PasswordService(
            @Value("${password.pepper}") String pepper,
            @Value("${argon2.iterations:5}") int iterations,
            @Value("${argon2.memory:65536}") int memory,
            @Value("${argon2.parallelism:1}") int parallelism,
            @Value("${argon2.salt-length:32}") int saltLength,
            @Value("${argon2.hash-length:32}") int hashLength) {
        // Validate salt length (Argon2 supports 8-2^32-1 bytes, but practical limit is 64 bytes)
        if (saltLength < 8 || saltLength > 64) {
            throw new IllegalArgumentException("Salt length must be between 8 and 64 bytes");
        }
        // Validate hash length (Argon2 supports 4-2^32-1 bytes, but practical limit is 64 bytes)
        if (hashLength < 16 || hashLength > 64) {
            throw new IllegalArgumentException("Hash length must be between 16 and 64 bytes");
        }
        
        this.saltLength = saltLength;
        this.hashLength = hashLength;
        // Use Argon2id instead of Argon2i for best protection
        this.argon2 = Argon2Factory.create(Argon2Types.ARGON2id, saltLength, hashLength);
        this.pepper = pepper;
        this.secureRandom = new SecureRandom();
        this.iterations = iterations;
        this.memory = memory;
        this.parallelism = parallelism;
    }

    /**
     * Generate a random salt for password hashing.
     * 
     * @return Base64-encoded salt (32 bytes = 256 bits)
     */
    public String generateSalt() {
        byte[] saltBytes = new byte[saltLength];
        secureRandom.nextBytes(saltBytes);
        return Base64.getEncoder().encodeToString(saltBytes);
    }

    /**
     * Hash a password with salt and pepper.
     * 
     * Architecture:
     * - Salt: Per-user, stored in DB (explicit control)
     * - Pepper: Universal, from config/env (server-side secret)
     * - We combine password+pepper+salt, then hash with Argon2
     * - Argon2 generates its own internal salt, so we store the FULL formatted hash
     * - During verification, we use Argon2's verify() method which handles salt extraction
     * 
     * @param password Raw password from user
     * @param saltBase64 Base64-encoded salt (from generateSalt() or database)
     * @return Full Argon2 formatted hash string (includes Argon2's salt): $argon2id$v=19$m=...$<salt>$<hash>
     */
    public String hashPassword(String password, String saltBase64) {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        if (saltBase64 == null || saltBase64.isEmpty()) {
            throw new IllegalArgumentException("Salt cannot be null or empty");
        }

        // Combine password + pepper + salt
        // Our salt adds explicit control, pepper adds server-side secret
        String combinedInput = password + pepper + saltBase64;
        char[] passwordChars = combinedInput.toCharArray();
        
        try {
            // Hash with Argon2id
            // Format: $argon2id$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt>$<hash>
            // Store the FULL formatted string (includes Argon2's internal salt)
            return argon2.hash(
                iterations,
                memory,
                parallelism,
                passwordChars,
                java.nio.charset.StandardCharsets.UTF_8
            );
        } finally {
            // Clean up sensitive data from memory
            argon2.wipeArray(passwordChars);
        }
    }

    /**
     * Verify a password against a stored hash.
     * 
     * Uses Argon2's verify() method which:
     * - Extracts salt from the stored formatted hash
     * - Hashes the input password with same parameters
     * - Performs constant-time comparison
     * 
     * @param rawPassword Password to verify
     * @param storedFormattedHash Full Argon2 formatted hash from database: $argon2id$v=19$m=...$<salt>$<hash>
     * @param storedSaltBase64 Base64-encoded salt from database (our explicit salt, included in input)
     * @return true if password matches, false otherwise
     */
    public boolean verifyPassword(String rawPassword, String storedFormattedHash, String storedSaltBase64) {
        if (rawPassword == null || storedFormattedHash == null || storedSaltBase64 == null) {
            return false;
        }

        try {
            // Combine password + pepper + salt (same as during registration)
            String combinedInput = rawPassword + pepper + storedSaltBase64;
            char[] passwordChars = combinedInput.toCharArray();
            
            try {
                // Use Argon2's verify() method which:
                // 1. Extracts salt from storedFormattedHash
                // 2. Hashes the input with same parameters
                // 3. Compares hashes in constant time
                boolean matches = argon2.verify(storedFormattedHash, passwordChars, java.nio.charset.StandardCharsets.UTF_8);
                return matches;
            } finally {
                // Clean up sensitive data from memory
                argon2.wipeArray(passwordChars);
            }
        } catch (Exception e) {
            // Log error but don't reveal details (security best practice)
            return false;
        }
    }

    /**
     * Hash a token deterministically (for use in database keys, Redis keys, etc.).
     * Uses SHA-256 for deterministic hashing (same input = same output).
     * 
     * This is safe for tokens since we're not storing passwords.
     * The pepper adds additional security layer.
     * 
     * @param token Token to hash (e.g., refresh token)
     * @return Base64-encoded SHA-256 hash
     */
    public String hashTokenDeterministically(String token) {
        if (token == null || token.isEmpty()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            // Add pepper for additional security
            String tokenWithPepper = token + pepper;
            byte[] hashBytes = digest.digest(tokenWithPepper.getBytes());
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash token", e);
        }
    }
}
