package com.ecom.identity.model.request;

/**
 * Logout request DTO
 * 
 * <p><b>WHAT THIS DOES:</b>
 * Request body for logout endpoint. Contains refresh token to revoke.
 * 
 * <p><b>COOKIE SUPPORT:</b>
 * If refreshToken is not provided in body, backend reads it from cookies.
 * This supports cookie-based authentication where tokens are in httpOnly cookies.
 * 
 * <p><b>HOW IT WORKS:</b>
 * - Mobile apps: Send refreshToken in request body
 * - Web browsers: refreshToken in httpOnly cookie (backend reads from cookie)
 * - Backend tries body first, then falls back to cookies
 * 
 * <p><b>WHY WE NEED THIS:</b>
 * - Hybrid approach: Supports both mobile (body) and web (cookies) clients
 * - Flexibility: Same API works for both platforms
 * - Security: Web browsers use httpOnly cookies (more secure)
 * 
 * <p><b>REAL-WORLD SCENARIO:</b>
 * Web browser logout → No refreshToken in body → Backend reads from cookie →
 * Backend revokes token → Backend clears cookies → User logged out
 */
public record LogoutRequest(
    // Refresh token is optional - can come from request body OR cookies
    // If not provided, backend reads from refreshToken cookie
    String refreshToken
) {
}

