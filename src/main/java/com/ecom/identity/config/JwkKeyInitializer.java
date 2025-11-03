package com.ecom.identity.config;

import com.ecom.identity.entity.JwkKey;
import com.ecom.identity.repository.JwkKeyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.Base64;

/**
 * JWT Key Initializer
 * 
 * <p>Automatically generates RSA key pairs for JWT signing on application startup
 * if no active keys exist in the database. This ensures the service can always
 * issue JWT tokens without manual key generation.
 * 
 * <p>Key Generation:
 * <ul>
 *   <li>RSA 2048-bit key pair (recommended for JWT signing)</li>
 *   <li>Key ID (kid) format: "key-{timestamp}"</li>
 *   <li>Expiration: 90 days from creation (configurable)</li>
 *   <li>Algorithm: RS256 (RSA with SHA-256)</li>
 * </ul>
 * 
 * <p>Note: In production, consider manual key rotation before expiration.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class JwkKeyInitializer {

    private final JwkKeyRepository jwkKeyRepository;
    
    private static final int KEY_EXPIRY_DAYS = 90;
    private static final int RSA_KEY_SIZE = 2048;

    @EventListener(ApplicationReadyEvent.class)
    public void initializeKeys() {
        log.info("Checking for active JWT keys...");
        
        // Check if any active (non-expired) keys exist
        LocalDateTime now = LocalDateTime.now();
        boolean hasActiveKey = jwkKeyRepository.findAll().stream()
            .anyMatch(key -> key.getExpiresAt() == null || key.getExpiresAt().isAfter(now));
        
        if (hasActiveKey) {
            log.info("Active JWT key found. Skipping key generation.");
            return;
        }
        
        log.info("No active JWT keys found. Generating new RSA key pair...");
        
        try {
            // Generate RSA key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(RSA_KEY_SIZE);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            
            // Convert keys to PEM format
            String publicKeyPem = convertToPEM(publicKey, false);
            String privateKeyPem = convertToPEM(privateKey, true);
            
            // Generate key ID (kid)
            String kid = "key-" + System.currentTimeMillis();
            
            // Create JwkKey entity
            JwkKey jwkKey = JwkKey.builder()
                .kid(kid)
                .publicKeyPem(publicKeyPem)
                .privateKeyPem(privateKeyPem)
                .algorithm("RS256")
                .expiresAt(LocalDateTime.now().plusDays(KEY_EXPIRY_DAYS))
                .build();
            
            // Save to database
            jwkKeyRepository.save(jwkKey);
            
            log.info("Successfully generated and saved JWT key pair: kid={}, expiresAt={}", 
                kid, jwkKey.getExpiresAt());
            
        } catch (Exception e) {
            log.error("Failed to generate JWT key pair. Service may not be able to issue tokens.", e);
            throw new RuntimeException("Failed to initialize JWT keys", e);
        }
    }
    
    /**
     * Convert RSA key to PEM format
     */
    private String convertToPEM(java.security.Key key, boolean isPrivate) {
        String header = isPrivate 
            ? "-----BEGIN PRIVATE KEY-----\n"
            : "-----BEGIN PUBLIC KEY-----\n";
        String footer = isPrivate
            ? "-----END PRIVATE KEY-----\n"
            : "-----END PUBLIC KEY-----\n";
        
        String base64Key = Base64.getMimeEncoder(64, new byte[]{'\n'})
            .encodeToString(key.getEncoded());
        
        return header + base64Key + "\n" + footer;
    }
}

