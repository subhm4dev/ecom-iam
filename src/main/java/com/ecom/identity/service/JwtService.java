package com.ecom.identity.service;

import com.ecom.identity.entity.JwkKey;
import com.ecom.identity.entity.UserAccount;
import com.ecom.identity.repository.JwkKeyRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * JWT Service for generating and managing JWT tokens
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class JwtService {

    private final JwkKeyRepository jwkKeyRepository;

    @Value("${jwt.access-token.expiry-hours:2}") // 2 hours - shorter for better security, refresh handles UX
    private int accessTokenExpiryHours;

    @Value("${jwt.refresh-token.expiry-days:30}") // 30 days - full session lifetime (like Amazon, Blinkit)
    private int refreshTokenExpiryDays;

    /**
     * Generate access token (2 hours expiry - short for security, auto-refreshed via refresh token)
     * 
     * <p>Strategy: Short access tokens (2 hours) + Long refresh tokens (30 days)
     * - Security: Compromised access tokens expire quickly
     * - UX: Refresh token auto-refreshes access token seamlessly (frontend handles)
     * - Logout: Blacklist access token + revoke refresh token = immediate logout
     */
    public String generateAccessToken(UserAccount user, List<String> roles) {
        try {
            JwkKey activeKey = getActiveKey();
            
            // Build JWT claims
            Date now = new Date();
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(user.getId().toString())
                .claim("userId", user.getId().toString())
                .claim("tenantId", user.getTenant().getId().toString())
                .claim("roles", roles)
                .claim("email", user.getEmail())
                .claim("phone", user.getPhone())
                .issueTime(now)
                .jwtID(UUID.randomUUID().toString()) // JWT ID (jti) for blacklisting
                .expirationTime(Date.from(Instant.now().plusSeconds(accessTokenExpiryHours * 3600L)))
                .issuer("ecom-identity")
                .build();

            // Sign with private key
            RSAPrivateKey privateKey = parsePrivateKey(activeKey.getPrivateKeyPem());
            JWSSigner signer = new RSASSASigner(privateKey);
            
            SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(activeKey.getKid())
                    .build(),
                claimsSet
            );
            
            signedJWT.sign(signer);
            return signedJWT.serialize();
            
        } catch (Exception e) {
            log.error("Failed to generate access token", e);
            throw new RuntimeException("Failed to generate access token", e);
        }
    }

    /**
     * Generate refresh token string (long-lived, 30 days)
     * This is just the token string - caller must store it in database
     * Matches modern e-commerce behavior - users stay logged in for weeks
     */
    public String generateRefreshTokenString() {
        // Generate a random UUID-based token
        return UUID.randomUUID().toString() + "-" + UUID.randomUUID().toString();
    }

    /**
     * Extract user ID from a token string
     * Used for extracting user context from JWT
     */
    public UUID extractUserId(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            String userId = signedJWT.getJWTClaimsSet().getSubject();
            return UUID.fromString(userId);
        } catch (Exception e) {
            log.error("Failed to extract user ID from token", e);
            throw new RuntimeException("Invalid token", e);
        }
    }

    /**
     * Extract JWT ID (jti) from a token string
     * Used for blacklisting tokens on logout
     */
    public String extractTokenId(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet().getJWTID();
        } catch (Exception e) {
            log.error("Failed to extract token ID", e);
            // Fallback: use token signature hash as ID
            return String.valueOf(token.hashCode());
        }
    }

    /**
     * Get remaining expiry time for a token (in seconds)
     * Used to set TTL for blacklisted tokens
     */
    public long getTokenExpirySeconds(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            Date expirationTime = signedJWT.getJWTClaimsSet().getExpirationTime();
            if (expirationTime == null) {
                return 0;
            }
            long remainingMs = expirationTime.getTime() - System.currentTimeMillis();
            return Math.max(0, remainingMs / 1000);
        } catch (Exception e) {
            log.error("Failed to extract token expiry", e);
            return 0;
        }
    }

    /**
     * Get active JWT signing key from database
     */
    private JwkKey getActiveKey() {
        LocalDateTime now = LocalDateTime.now();
        
        return jwkKeyRepository.findAll().stream()
            .filter(key -> key.getExpiresAt() == null || key.getExpiresAt().isAfter(now))
            .findFirst()
            .orElseThrow(() -> new RuntimeException("No active JWT key found. Ensure key initialization has run."));
    }

    /**
     * Parse RSA private key from PEM format
     */
    private RSAPrivateKey parsePrivateKey(String privateKeyPem) {
        try {
            // Remove PEM headers and whitespace
            String privateKeyContent = privateKeyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
            
            byte[] keyBytes = Base64.getDecoder().decode(privateKeyContent);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
            
        } catch (Exception e) {
            log.error("Failed to parse private key", e);
            throw new RuntimeException("Failed to parse private key", e);
        }
    }
}

