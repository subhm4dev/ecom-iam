package com.ecom.identity.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Session Management Service
 * 
 * <p>Manages user sessions using Redis for:
 * <ul>
 *   <li>Token blacklisting (revoked access tokens)</li>
 *   <li>Active session tracking per user</li>
 *   <li>Multi-device session management</li>
 * </ul>
 * 
 * <p>Why Redis for blacklisting:
 * <ul>
 *   <li>Fast lookups (O(1) complexity)</li>
 *   <li>Automatic expiration (TTL matches token expiry)</li>
 *   <li>Distributed (works across multiple gateway instances)</li>
 *   <li>Memory-efficient (only stores token IDs, not full tokens)</li>
 * </ul>
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class SessionService {

    private final RedisTemplate<String, String> redisTemplate;
    
    private static final String BLACKLIST_PREFIX = "jwt:blacklist:";
    private static final String SESSION_PREFIX = "session:";
    private static final String USER_SESSIONS_PREFIX = "user:sessions:";

    /**
     * Blacklist an access token (mark as revoked)
     * 
     * <p>When user logs out, we blacklist their access token so Gateway
     * can reject it immediately, even before it expires.
     * 
     * <p>Token ID is derived from JWT jti (JWT ID) claim or computed from
     * token signature for uniqueness.
     * 
     * @param tokenId Unique identifier for the token (jti claim or signature hash)
     * @param expiresInSeconds Time until token naturally expires (for TTL)
     */
    public void blacklistToken(String tokenId, long expiresInSeconds) {
        String key = BLACKLIST_PREFIX + tokenId;
        redisTemplate.opsForValue().set(key, "revoked", expiresInSeconds, TimeUnit.SECONDS);
        log.debug("Token blacklisted: {}", tokenId);
    }

    /**
     * Check if a token is blacklisted
     * 
     * <p>Gateway calls this (or checks Redis directly) to validate tokens
     * before allowing requests to pass through.
     */
    public boolean isTokenBlacklisted(String tokenId) {
        String key = BLACKLIST_PREFIX + tokenId;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    /**
     * Track an active session for a user
     * 
     * <p>Stores session metadata (device info, IP, last activity) to support:
     * <ul>
     *   <li>Multi-device login tracking</li>
     *   <li>"Logout all devices" functionality</li>
     *   <li>Session management UI</li>
     * </ul>
     * 
     * @param userId User ID
     * @param sessionId Unique session identifier
     * @param deviceInfo Optional device/browser info
     * @param expiresInSeconds Session expiry time
     */
    public void trackSession(UUID userId, String sessionId, String deviceInfo, long expiresInSeconds) {
        // Store session details
        String sessionKey = SESSION_PREFIX + sessionId;
        redisTemplate.opsForValue().set(sessionKey, userId.toString(), expiresInSeconds, TimeUnit.SECONDS);
        
        // Track all sessions for this user
        String userSessionsKey = USER_SESSIONS_PREFIX + userId;
        redisTemplate.opsForSet().add(userSessionsKey, sessionId);
        redisTemplate.expire(userSessionsKey, expiresInSeconds, TimeUnit.SECONDS);
        
        log.debug("Session tracked: userId={}, sessionId={}", userId, sessionId);
    }

    /**
     * Revoke a specific session (logout from one device)
     */
    public void revokeSession(UUID userId, String sessionId) {
        String sessionKey = SESSION_PREFIX + sessionId;
        redisTemplate.delete(sessionKey);
        
        String userSessionsKey = USER_SESSIONS_PREFIX + userId;
        redisTemplate.opsForSet().remove(userSessionsKey, sessionId);
        
        log.debug("Session revoked: userId={}, sessionId={}", userId, sessionId);
    }

    /**
     * Revoke all sessions for a user (logout from all devices)
     * 
     * <p>Used when:
     * <ul>
     *   <li>User clicks "Logout from all devices"</li>
     *   <li>Password changed (security best practice)</li>
     *   <li>Admin revokes user access</li>
     * </ul>
     */
    public void revokeAllUserSessions(UUID userId) {
        String userSessionsKey = USER_SESSIONS_PREFIX + userId;
        Set<String> sessionIds = redisTemplate.opsForSet().members(userSessionsKey);
        
        if (sessionIds != null) {
            sessionIds.forEach(sessionId -> {
                String sessionKey = SESSION_PREFIX + sessionId;
                redisTemplate.delete(sessionKey);
            });
            redisTemplate.delete(userSessionsKey);
            log.info("All sessions revoked for user: {}", userId);
        }
    }

    /**
     * Get all active sessions for a user
     * 
     * <p>Used for session management UI (e.g., "Active Sessions" page)
     */
    public Set<String> getUserSessions(UUID userId) {
        String userSessionsKey = USER_SESSIONS_PREFIX + userId;
        return redisTemplate.opsForSet().members(userSessionsKey);
    }
}

