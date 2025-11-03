package com.ecom.identity.service;

import com.ecom.identity.entity.JwkKey;
import com.ecom.identity.repository.JwkKeyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * JWKS Service for generating JSON Web Key Set format
 * 
 * <p>Converts RSA public keys from database to JWKS format (RFC 7517).
 * Gateway service uses this to verify JWT tokens.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class JwksService {

    private final JwkKeyRepository jwkKeyRepository;

    /**
     * Get JWKS (JSON Web Key Set) for all active keys
     * 
     * @return Map containing "keys" array with JWK objects
     */
    public Map<String, Object> getJwks() {
        List<Map<String, Object>> keys = new ArrayList<>();
        
        // Get all active (non-expired) keys
        LocalDateTime now = LocalDateTime.now();
        List<JwkKey> activeKeys = jwkKeyRepository.findAll().stream()
            .filter(key -> key.getExpiresAt() == null || key.getExpiresAt().isAfter(now))
            .toList();
        
        // Convert each key to JWK format
        for (JwkKey jwkKey : activeKeys) {
            try {
                Map<String, Object> jwk = convertToJwk(jwkKey);
                keys.add(jwk);
            } catch (Exception e) {
                log.error("Failed to convert JwkKey to JWK format: kid={}", jwkKey.getKid(), e);
                // Continue with other keys even if one fails
            }
        }
        
        return Map.of("keys", keys);
    }

    /**
     * Convert JwkKey entity to JWK (JSON Web Key) format
     * 
     * @param jwkKey JwkKey entity from database
     * @return Map representing JWK object (RFC 7517)
     */
    private Map<String, Object> convertToJwk(JwkKey jwkKey) throws Exception {
        // Parse RSA public key from PEM format
        RSAPublicKey publicKey = parsePublicKey(jwkKey.getPublicKeyPem());
        
        // Extract modulus (n) and exponent (e)
        BigInteger modulus = publicKey.getModulus();
        BigInteger exponent = publicKey.getPublicExponent();
        
        // Encode to Base64URL (RFC 7515 Section 2)
        // BigInteger.toByteArray() returns signed two's complement, but for positive
        // integers (modulus and exponent always are), we may need to remove leading zero byte
        String modulusBase64Url = base64UrlEncode(toUnsignedByteArray(modulus));
        String exponentBase64Url = base64UrlEncode(toUnsignedByteArray(exponent));
        
        // Build JWK object (RFC 7517)
        return Map.of(
            "kty", "RSA",
            "kid", jwkKey.getKid(),
            "use", "sig",
            "alg", jwkKey.getAlgorithm(),
            "n", modulusBase64Url,
            "e", exponentBase64Url
        );
    }

    /**
     * Parse RSA public key from PEM format
     */
    private RSAPublicKey parsePublicKey(String publicKeyPem) throws Exception {
        // Remove PEM headers and whitespace
        String publicKeyContent = publicKeyPem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
        
        // Decode Base64
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyContent);
        
        // Parse X.509 encoded public key
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    /**
     * Convert BigInteger to unsigned byte array (removes leading zero if present)
     * 
     * BigInteger.toByteArray() may add a leading zero byte for positive numbers
     * where the high bit is set. For JWKS, we want minimal encoding.
     */
    private byte[] toUnsignedByteArray(BigInteger value) {
        byte[] bytes = value.toByteArray();
        // Remove leading zero byte if present (for positive numbers with high bit set)
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] result = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, result, 0, result.length);
            return result;
        }
        return bytes;
    }

    /**
     * Encode bytes to Base64URL (RFC 7515 Section 2)
     * 
     * Base64URL encoding:
     * - Uses '-' instead of '+' 
     * - Uses '_' instead of '/'
     * - Omits padding '=' characters
     */
    private String base64UrlEncode(byte[] bytes) {
        // Use Base64 URL-safe encoding, then remove padding
        String base64 = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        return base64;
    }
}

