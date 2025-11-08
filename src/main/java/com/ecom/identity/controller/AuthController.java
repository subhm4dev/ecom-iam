package com.ecom.identity.controller;

import com.ecom.identity.service.AuthService;
import com.ecom.identity.service.CookieService;
import com.ecom.error.exception.BusinessException;
import com.ecom.error.model.ErrorCode;
import com.ecom.response.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import com.ecom.identity.model.request.LoginRequest;
import com.ecom.identity.model.request.LogoutRequest;
import com.ecom.identity.model.request.RefreshRequest;
import com.ecom.identity.model.request.RegisterRequest;
import com.ecom.identity.model.response.LoginResponse;
import com.ecom.identity.model.response.RefreshResponse;
import com.ecom.identity.model.response.RegisterResponse;
import com.ecom.identity.service.JwtService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

/**
 * Authentication Controller
 *
 * <p>This controller handles user authentication flows including registration, login,
 * token refresh, and logout operations. These endpoints are essential for establishing
 * user identity and securing access to other services in the e-commerce platform.
 *
 * <p>Why we need these APIs:
 * <ul>
 *   <li><b>Registration:</b> Allows new users (customers, sellers) to create accounts
 *       with email or phone authentication. Critical for onboarding and multi-tenant support.</li>
 *   <li><b>Login:</b> Authenticates users and issues JWT tokens (access + refresh)
 *       for subsequent API calls. Gateway validates these tokens to authorize requests.</li>
 *   <li><b>Token Refresh:</b> Extends user sessions without requiring re-authentication,
 *       improving UX while maintaining security through short-lived access tokens.</li>
 *   <li><b>Logout:</b> Revokes refresh tokens to prevent unauthorized access after
 *       user-initiated logout, essential for security and compliance.</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "User authentication and authorization endpoints")
public class AuthController {
    private final AuthService authService;
    private final JwtService jwtService;
    private final CookieService cookieService;

    @Value("${jwt.refresh-token.expiry-days:30}")
    private int refreshTokenExpiryDays;

    /**
     * Register a new user account
     *
     * <p>This endpoint enables user registration with flexible authentication options.
     * Users can register using either email OR phone number, supporting diverse
     * user bases across different regions. The registration process:
     * <ul>
     *   <li>Validates that either email or phone is provided (not both required)</li>
     *   <li>Checks uniqueness of email/phone within tenant scope</li>
     *   <li>Hashes password using Argon2 with salt+pepper technique</li>
     *   <li>Assigns roles (CUSTOMER, SELLER, etc.) based on tenant context</li>
     *   <li>Auto-logs in user by generating tokens and setting cookies</li>
     * </ul>
     *
     * <p><b>COOKIE HANDLING:</b>
     * After successful registration, this endpoint sets httpOnly cookies containing
     * access and refresh tokens. This enables:
     * - Web browsers to automatically send tokens with requests (no manual header management)
     * - Mobile apps to receive tokens in response body (same API, different storage)
     * - Hybrid approach: Web uses cookies, mobile uses Keychain/Keystore
     * 
     * <p><b>REAL-WORLD SCENARIO:</b>
     * User fills registration form → Submits → Backend creates account → 
     * Backend generates tokens → Backend sets cookies → User is automatically logged in →
     * Browser stores cookies → Next API call includes cookies automatically → User authenticated
     *
     * <p>This is a public endpoint (no authentication required) as it's the entry point
     * for new users to join the platform.
     */
    @PostMapping("/register")
    @Operation(
        summary = "Register a new user account",
        description = "Creates a new user account with email or phone authentication. Supports multi-tenant registration. Auto-logs in user and sets authentication cookies.",
        security = {}
    )
    public RegisterResponse register(
            @Valid @RequestBody RegisterRequest registerRequest,
            HttpServletResponse response) {
        
        // Register user and get tokens (auto-login after registration)
        RegisterResponse registerResponse = authService.register(registerRequest);
        
        // Set authentication cookies for web browsers
        // WHAT: Creates httpOnly cookies with access and refresh tokens
        // HOW: CookieService sets cookies in response headers
        // WHY: Web browsers automatically send cookies with requests (better UX, more secure)
        // REAL-WORLD: User registers → Cookies set → Browser stores them → User stays logged in
        // NOTE: Mobile apps ignore cookies and use tokens from response body (stored in Keychain/Keystore)
        cookieService.setAuthCookies(
            response,
            registerResponse.token(), // Access token (RegisterResponse uses "token" field name)
            registerResponse.refreshToken(),
            2L * 3600L, // Access token expiry: 2 hours (7200 seconds)
            refreshTokenExpiryDays // Refresh token expiry: 30 days (from config)
        );
        
        // Return response with tokens (for mobile apps and backward compatibility)
        // Web browsers will use cookies, mobile apps will use response body
        return registerResponse;
    }

    /**
     * Authenticate user and issue JWT tokens
     *
     * <p>This endpoint authenticates existing users and issues JWT tokens for accessing
     * protected resources. Users can login with either email or phone number, providing
     * flexibility in authentication methods.
     *
     * <p>The authentication flow:
     * <ul>
     *   <li>Accepts email OR phone along with password</li>
     *   <li>Validates credentials using PasswordService.matches()</li>
     *   <li>Generates short-lived access token (2 hours) via JwtService</li>
     *   <li>Generates long-lived refresh token (30 days) for session extension</li>
     *   <li>Sets httpOnly cookies with tokens (for web browsers)</li>
     *   <li>Returns tokens in response body (for mobile apps and backward compatibility)</li>
     * </ul>
     *
     * <p><b>COOKIE HANDLING:</b>
     * This endpoint sets httpOnly cookies containing access and refresh tokens.
     * - <b>Web browsers:</b> Cookies are automatically sent with requests (no manual header management)
     * - <b>Mobile apps:</b> Ignore cookies, use tokens from response body (store in Keychain/Keystore)
     * - <b>Hybrid approach:</b> Same API works for both web and mobile, each uses appropriate storage
     * 
     * <p><b>REAL-WORLD SCENARIO:</b>
     * User enters credentials → Clicks "Login" → Backend validates → 
     * Backend generates tokens → Backend sets cookies → User is logged in →
     * Browser stores cookies → Next API call automatically includes cookies → Gateway validates → User authenticated
     *
     * <p>Gateway validates the returned access token for all downstream service calls.
     * This endpoint is public (no authentication required) as it's the entry point
     * for user authentication.
     */
    @PostMapping("/login")
    @Operation(
        summary = "Authenticate user and get JWT tokens",
        description = "Validates user credentials and returns access token + refresh token. Sets httpOnly cookies for web browsers.",
        security = {}
    )
    public LoginResponse login(
            @Valid @RequestBody LoginRequest loginRequest,
            HttpServletResponse response) {
        
        // Authenticate user and get tokens
        LoginResponse loginResponse = authService.login(loginRequest);
        
        // Set authentication cookies for web browsers
        // WHAT: Creates httpOnly cookies with access and refresh tokens
        // HOW: CookieService sets cookies in response headers
        // WHY: Web browsers automatically send cookies with requests (better UX, more secure than localStorage)
        // REAL-WORLD: User logs in → Cookies set → Browser stores them → User stays logged in for 30 days
        // NOTE: Mobile apps ignore cookies and use tokens from response body (stored in Keychain/Keystore)
        cookieService.setAuthCookies(
            response,
            loginResponse.accessToken(),
            loginResponse.refreshToken(),
            loginResponse.expiresIn(), // Access token expiry in seconds (from service)
            refreshTokenExpiryDays // Refresh token expiry: 30 days (from config)
        );
        
        // Return response with tokens (for mobile apps and backward compatibility)
        // Web browsers will use cookies, mobile apps will use response body
        return loginResponse;
    }

    /**
     * Refresh access token using refresh token
     *
     * <p>This endpoint allows clients to obtain a new access token without requiring
     * the user to re-enter credentials. It's essential for maintaining seamless user
     * experience while keeping access tokens short-lived for security.
     *
     * <p>The refresh flow:
     * <ul>
     *   <li>Validates the refresh token (not expired, not revoked)</li>
     *   <li>If access token is provided, validates it belongs to same user as refresh token</li>
     *   <li>Issues a new access token with updated expiration</li>
     *   <li>Updates access token cookie (refresh token cookie remains unchanged)</li>
     *   <li>Maintains session continuity without re-authentication</li>
     * </ul>
     *
     * <p><b>COOKIE HANDLING:</b>
     * When refresh succeeds, this endpoint updates the access token cookie with the new token.
     * The refresh token cookie remains unchanged (it's long-lived, 30 days).
     * - <b>Web browsers:</b> Cookie is automatically updated, browser sends new token with next request
     * - <b>Mobile apps:</b> Ignore cookies, use new access token from response body
     * 
     * <p><b>REAL-WORLD SCENARIO:</b>
     * Access token expires (2 hours) → Frontend calls refresh endpoint →
     * Backend validates refresh token → Backend issues new access token →
     * Backend updates access token cookie → User continues using app without re-login
     *
     * <p>Note: This endpoint is public (no authentication required) because access tokens
     * may have expired. However, if an access token is provided, it must belong to the
     * same user as the refresh token for security validation.
     */
    @PostMapping("/refresh")
    @Operation(
        summary = "Refresh access token",
        description = "Issues a new access token using a valid refresh token. Updates access token cookie for web browsers.",
        security = {}
    )
    public RefreshResponse refreshToken(
            @Valid @RequestBody RefreshRequest refreshRequest,
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader,
            HttpServletResponse response) {
        // Extract access token if provided (optional - access token may be expired)
        String accessToken = null;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            accessToken = authorizationHeader.substring(7);
        }
        
        // Refresh token and get new access token
        RefreshResponse refreshResponse = authService.refresh(refreshRequest, accessToken);
        
        // Update access token cookie with new token
        // WHAT: Updates the access token cookie (refresh token cookie stays the same)
        // HOW: CookieService sets new cookie with updated access token
        // WHY: Web browsers need updated cookie to send new token with next request
        // REAL-WORLD: Token expires → Refresh called → New token generated → Cookie updated → User continues
        // NOTE: We need the refresh token from the request to update both cookies
        // Since refresh token doesn't change, we use the one from the request
        cookieService.setAuthCookies(
            response,
            refreshResponse.accessToken(), // New access token
            refreshRequest.refreshToken(), // Same refresh token (unchanged)
            refreshResponse.expiresIn(), // New access token expiry: 2 hours
            refreshTokenExpiryDays // Refresh token expiry: 30 days (unchanged)
        );
        
        // Return response with new access token (for mobile apps and backward compatibility)
        return refreshResponse;
    }

    /**
     * Logout user and revoke refresh token
     *
     * <p>This endpoint invalidates the user's refresh token and blacklists their
     * access token, effectively ending their session immediately. This is critical for:
     * <ul>
     *   <li>Security: Prevents token reuse after logout (blacklist in Redis)</li>
     *   <li>Compliance: Ensures proper session termination</li>
     *   <li>UX: Allows users to explicitly end their session</li>
     * </ul>
     *
     * <p>The logout process:
     * <ul>
     *   <li>Validates that the user is authenticated (access token required)</li>
     *   <li>Validates that refresh token belongs to the authenticated user</li>
     *   <li>Revokes the refresh token (marks as revoked in database)</li>
     *   <li>Blacklists the access token in Redis (Gateway rejects it immediately)</li>
     *   <li>Clears authentication cookies (browser removes them automatically)</li>
     * </ul>
     *
     * <p><b>COOKIE HANDLING:</b>
     * After revoking tokens, this endpoint clears authentication cookies by setting
     * them to expire immediately. The browser will automatically delete these cookies.
     * - <b>Web browsers:</b> Cookies are deleted, user is logged out immediately
     * - <b>Mobile apps:</b> Ignore cookies, tokens are revoked server-side (app should clear local storage)
     * 
     * <p><b>REAL-WORLD SCENARIO:</b>
     * User clicks "Logout" → Backend revokes tokens → Backend clears cookies →
     * Browser deletes cookies → Next request has no cookies → User is not authenticated →
     * User is redirected to login page
     *
     * <p>This endpoint requires authentication to ensure only logged-in users can logout,
     * preventing unauthorized logout attempts with stolen refresh tokens.
     */
    @PostMapping("/logout")
    @Operation(
        summary = "Logout user and revoke refresh token",
        description = "Requires authentication. Invalidates refresh token, blacklists access token, and clears authentication cookies. Refresh token can be provided in request body (mobile) or cookie (web).",
        security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ApiResponse<Void> logout(
            @RequestBody(required = false) LogoutRequest logoutRequest,
            @RequestHeader("Authorization") String authorizationHeader,
            @CookieValue(value = "refreshToken", required = false) String refreshTokenCookie,
            HttpServletResponse response) {
        // Extract access token from Authorization header (required)
        String accessToken = authorizationHeader.substring(7); // Remove "Bearer "
        
        // Get refresh token from request body OR cookies (hybrid approach)
        // WHAT: Tries request body first, falls back to cookies
        // HOW: Checks logoutRequest.refreshToken(), then refreshTokenCookie
        // WHY: Supports both mobile apps (body) and web browsers (cookies)
        // REAL-WORLD: Web browser → refreshToken in cookie → Backend reads cookie
        //             Mobile app → refreshToken in body → Backend reads body
        String refreshToken = null;
        if (logoutRequest != null && logoutRequest.refreshToken() != null && !logoutRequest.refreshToken().isBlank()) {
            // Refresh token provided in request body (mobile apps)
            refreshToken = logoutRequest.refreshToken();
        } else if (refreshTokenCookie != null && !refreshTokenCookie.isBlank()) {
            // Refresh token in cookie (web browsers)
            refreshToken = refreshTokenCookie;
        }
        
        // Validate refresh token is available (from body or cookie)
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new BusinessException(ErrorCode.BAD_CREDENTIALS, "Refresh token is required (provide in request body or cookie)");
        }
        
        // Create LogoutRequest with resolved refresh token
        LogoutRequest resolvedRequest = new LogoutRequest(refreshToken);
        
        // Revoke tokens (database + Redis blacklist)
        authService.logout(resolvedRequest, accessToken);
        
        // Clear authentication cookies
        // WHAT: Removes cookies by setting them to expire immediately
        // HOW: CookieService sets cookies with MaxAge=0
        // WHY: Browser needs to be told to delete cookies (server-side revocation isn't enough)
        // REAL-WORLD: User logs out → Cookies deleted → Next request has no cookies → User not authenticated
        cookieService.clearAuthCookies(response);
        
        return ApiResponse.success(null, "User logged out successfully");
    }

    /**
     * Logout user from all devices
     *
     * <p>This endpoint revokes all active sessions for the authenticated user,
     * effectively logging them out from all devices. Useful for:
     * <ul>
     *   <li>Security: When user suspects account compromise</li>
     *   <li>Password reset: Automatically logout all devices after password change</li>
     *   <li>UX: "Logout from all devices" feature in account settings</li>
     * </ul>
     *
     * <p>The process:
     * <ul>
     *   <li>Revokes all refresh tokens for the user (database)</li>
     *   <li>Blacklists all access tokens in Redis</li>
     *   <li>Clears all session tracking for the user</li>
     *   <li>Clears authentication cookies on current device (browser removes them)</li>
     * </ul>
     *
     * <p><b>COOKIE HANDLING:</b>
     * After revoking all tokens, this endpoint also clears cookies on the current device.
     * Other devices' cookies remain until they try to use revoked tokens (then they'll be rejected).
     * - <b>Web browsers:</b> Current device's cookies are deleted immediately
     * - <b>Other devices:</b> Cookies remain but tokens are revoked (next request will fail)
     * - <b>Mobile apps:</b> Ignore cookies, tokens are revoked server-side (app should clear local storage)
     * 
     * <p><b>REAL-WORLD SCENARIO:</b>
     * User suspects account hack → Clicks "Logout from all devices" →
     * Backend revokes all tokens → Backend clears current device cookies →
     * All devices logged out → User must login again on all devices
     *
     * <p>This endpoint requires authentication (user must be logged in to logout everywhere).
     */
    @PostMapping("/logout-all")
    @Operation(
        summary = "Logout from all devices",
        description = "Revokes all active sessions and tokens for the authenticated user across all devices. Clears cookies on current device.",
        security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ApiResponse<Void> logoutAll(
            @RequestHeader("Authorization") String authorizationHeader,
            HttpServletResponse response) {
        // Extract access token and user info
        String accessToken = authorizationHeader.substring(7); // Remove "Bearer "
        java.util.UUID userId = jwtService.extractUserId(accessToken);
        
        // Revoke all tokens (database + Redis blacklist)
        authService.logoutAll(userId, accessToken);
        
        // Clear authentication cookies on current device
        // WHAT: Removes cookies by setting them to expire immediately
        // HOW: CookieService sets cookies with MaxAge=0
        // WHY: Current device needs cookies cleared (other devices' cookies remain but tokens are revoked)
        // REAL-WORLD: User logs out from all → Current device cookies deleted → Other devices' tokens revoked →
        // Other devices will fail on next request → User must login again everywhere
        cookieService.clearAuthCookies(response);
        
        return ApiResponse.success(null, "User logged out successfully from all devices");
    }
}

