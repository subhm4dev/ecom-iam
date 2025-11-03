# Session Management & Logout Strategy

## Overview

This document outlines the session management and logout strategy for the e-commerce identity service. The approach balances security with user experience (UX), following patterns used by modern e-commerce platforms like Amazon and Blinkit.

## Architecture

### Token Strategy

**Short Access Tokens (2 hours) + Long Refresh Tokens (30 days)**

- **Access Token**: Short-lived (2 hours) for security
  - Automatically refreshed by frontend using refresh token
  - Contains user ID, tenant ID, roles, email, phone
  - Includes JWT ID (`jti`) for blacklisting
  - Stored in memory on client (browser/app)

- **Refresh Token**: Long-lived (30 days) for UX
  - Stored securely on client (HttpOnly cookie recommended)
  - Used to obtain new access tokens seamlessly
  - Stored in database (`refresh_tokens` table)
  - Can be revoked independently

### Why This Approach?

1. **Security**: Compromised access tokens expire quickly (2 hours)
2. **UX**: Users stay logged in for 30 days (no frequent re-login)
3. **Logout**: Immediate revocation via blacklisting + token revocation
4. **Multi-device**: Each device gets separate refresh token

## Components

### 1. SessionService

Manages sessions using **Redis** for:
- **Token Blacklisting**: Revoked access tokens stored with TTL
- **Active Session Tracking**: Track sessions per user
- **Multi-device Management**: Support logout from all devices

**Redis Keys:**
- `jwt:blacklist:{tokenId}` - Blacklisted access tokens (TTL = token expiry)
- `session:{sessionId}` - Session metadata (TTL = token expiry)
- `user:sessions:{userId}` - Set of all active sessions for user

### 2. Logout Flows

#### Single Device Logout (`/api/v1/auth/logout`)

```
1. Client sends refresh token + access token (optional)
2. Service revokes refresh token (sets revoked = true in DB)
3. Service blacklists access token in Redis (if provided)
4. Gateway rejects any requests with blacklisted token
```

**When to use:**
- User clicks "Logout" button
- Session timeout (frontend-initiated)
- User switches accounts

#### All Devices Logout (`/api/v1/auth/logout-all`)

```
1. Client sends access token (authenticated request)
2. Service extracts user ID from token
3. Service revokes ALL refresh tokens for user (database)
4. Service revokes ALL sessions in Redis
5. All devices logged out immediately
```

**When to use:**
- User suspects account compromise
- Password change (security best practice)
- "Logout from all devices" feature in account settings
- Admin action (suspend user account)

### 3. Gateway Integration

The Gateway service should:

1. **Validate JWT Signature**: Using JWKS endpoint from Identity service
2. **Check Token Expiry**: Reject expired tokens (401)
3. **Check Blacklist**: Query Redis for `jwt:blacklist:{tokenId}`
   - If found, reject request (401 Unauthorized)
   - If not found, allow request to proceed
4. **Extract User Context**: Pass user ID, tenant ID, roles to downstream services

**Example Gateway Filter (pseudo-code):**
```java
String token = extractToken(request);
String tokenId = jwtService.extractTokenId(token);

if (sessionService.isTokenBlacklisted(tokenId)) {
    return 401 Unauthorized;
}

// Proceed with request...
```

## Configuration

### Application Properties

```yaml
jwt:
  access-token:
    expiry-hours: 2  # Short for security
  refresh-token:
    expiry-days: 30  # Long for UX

spring:
  data:
    redis:
      host: ${REDIS_HOST:localhost}
      port: ${REDIS_PORT:6379}
```

### Token Expiry Recommendations

| Token Type | Expiry | Reasoning |
|------------|--------|-----------|
| Access Token | 1-2 hours | Balance between security and refresh frequency |
| Refresh Token | 30 days | Match modern e-commerce UX (Amazon, Blinkit) |
| Blacklist TTL | Same as token expiry | Auto-cleanup expired blacklist entries |

## Security Considerations

### 1. Token Storage

**Client-side:**
- Access token: Memory or secure storage (never localStorage)
- Refresh token: HttpOnly cookie (web) or secure storage (mobile)

**Server-side:**
- Refresh tokens: Database (with hashing)
- Blacklist: Redis (in-memory, fast lookups)

### 2. Token Blacklisting

**Why Redis?**
- Fast lookups: O(1) complexity
- Automatic cleanup: TTL matches token expiry
- Distributed: Works across multiple Gateway instances
- Memory-efficient: Only stores token IDs, not full tokens

**Alternative Approaches Considered:**
1. ❌ Token versioning: Requires DB lookup on every request (slower)
2. ❌ Database blacklist: Too slow for high-traffic scenarios
3. ✅ Redis blacklist: Fast, distributed, auto-cleanup (chosen)

### 3. Refresh Token Security

- **Hashing**: Stored as hash in database (not plain text)
- **Revocation**: Can be revoked individually or all at once
- **Expiry**: 30 days (can be adjusted per requirement)

### 4. Multi-Device Handling

- Each login creates a new refresh token
- Users can see all active sessions (future feature)
- Users can logout from specific devices (future feature)
- "Logout all" immediately revokes everything

## Usage Examples

### Logout (Single Device)

```bash
POST /api/v1/auth/logout
Content-Type: application/json
Authorization: Bearer <access_token>

{
  "refreshToken": "uuid-uuid-uuid-uuid"
}
```

### Logout All Devices

```bash
POST /api/v1/auth/logout-all
Authorization: Bearer <access_token>
```

## Frontend Integration

### Auto-Refresh Pattern

```javascript
// Intercept 401 responses
axios.interceptors.response.use(
  response => response,
  async error => {
    if (error.response?.status === 401) {
      // Try to refresh token
      const newAccessToken = await refreshAccessToken();
      // Retry original request with new token
      return axios.request(error.config);
    }
    return Promise.reject(error);
  }
);
```

### Logout Flow

```javascript
async function logout() {
  // 1. Revoke refresh token
  await axios.post('/api/v1/auth/logout', {
    refreshToken: getRefreshToken()
  });
  
  // 2. Clear local tokens
  clearAccessToken();
  clearRefreshToken();
  
  // 3. Redirect to login
  router.push('/login');
}
```

## Future Enhancements

1. **Session Management UI**: Show active sessions, logout from specific devices
2. **Session Metadata**: Track device info, IP, last activity
3. **Suspicious Activity Detection**: Alert on multiple logins from different locations
4. **Remember Me**: Extend refresh token to 90 days if "remember me" checked
5. **Token Rotation**: Rotate refresh tokens on each use (enhanced security)

## Troubleshooting

### Issue: Token still valid after logout

**Check:**
1. Is Gateway checking Redis blacklist?
2. Is blacklist TTL set correctly?
3. Is token ID (`jti`) being extracted correctly?

### Issue: Redis connection failed

**Solution:**
1. Ensure Redis is running (`docker compose up redis`)
2. Check Redis connection in `application.yml`
3. Verify Redis health in Gateway service

### Issue: Logout not working

**Check:**
1. Is refresh token being hashed correctly?
2. Is token lookup finding the correct record?
3. Are both access and refresh tokens being handled?

## References

- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [OAuth 2.0 Refresh Tokens](https://oauth.net/2/refresh-tokens/)
- [Spring Security JWT](https://spring.io/guides/tutorials/spring-boot-oauth2/)
- [Redis Best Practices](https://redis.io/docs/manual/patterns/)

