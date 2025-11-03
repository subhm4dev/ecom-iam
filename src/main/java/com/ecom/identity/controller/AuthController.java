package com.ecom.identity.controller;

import com.ecom.identity.service.AuthService;
import com.ecom.response.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
     * </ul>
     *
     * <p>This is a public endpoint (no authentication required) as it's the entry point
     * for new users to join the platform.
     */
    @PostMapping("/register")
    @Operation(
        summary = "Register a new user account",
        description = "Creates a new user account with email or phone authentication. Supports multi-tenant registration.",
        security = {}
    )
    public RegisterResponse register(@Valid @RequestBody RegisterRequest registerRequest) {
        return authService.register(registerRequest);
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
     *   <li>Generates short-lived access token (15 min) via JwtService</li>
     *   <li>Generates long-lived refresh token (7 days) for session extension</li>
     *   <li>Returns tokens to client for subsequent API calls</li>
     * </ul>
     *
     * <p>Gateway validates the returned access token for all downstream service calls.
     * This endpoint is public (no authentication required) as it's the entry point
     * for user authentication.
     */
    @PostMapping("/login")
    @Operation(
        summary = "Authenticate user and get JWT tokens",
        description = "Validates user credentials and returns access token + refresh token for API authentication",
        security = {}
    )
    public LoginResponse login(@Valid @RequestBody LoginRequest loginRequest) {
        return authService.login(loginRequest);
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
     *   <li>Maintains session continuity without re-authentication</li>
     * </ul>
     *
     * <p>Note: This endpoint is public (no authentication required) because access tokens
     * may have expired. However, if an access token is provided, it must belong to the
     * same user as the refresh token for security validation.
     */
    @PostMapping("/refresh")
    @Operation(
        summary = "Refresh access token",
        description = "Issues a new access token using a valid refresh token. Validates user match if access token provided.",
        security = {}
    )
    public RefreshResponse refreshToken(
            @Valid @RequestBody RefreshRequest refreshRequest,
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader) {
        // Extract access token if provided (optional - access token may be expired)
        String accessToken = null;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            accessToken = authorizationHeader.substring(7);
        }
        
        return authService.refresh(refreshRequest, accessToken);
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
     * </ul>
     *
     * <p>This endpoint requires authentication to ensure only logged-in users can logout,
     * preventing unauthorized logout attempts with stolen refresh tokens.
     */
    @PostMapping("/logout")
    @Operation(
        summary = "Logout user and revoke refresh token",
        description = "Requires authentication. Invalidates refresh token and blacklists access token to end user session securely",
        security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ApiResponse<Void> logout(
            @Valid @RequestBody LogoutRequest logoutRequest,
            @RequestHeader("Authorization") String authorizationHeader) {
        // Extract access token from Authorization header (required)
        String accessToken = authorizationHeader.substring(7); // Remove "Bearer "
        
        authService.logout(logoutRequest, accessToken);
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
     * </ul>
     *
     * <p>This endpoint requires authentication (user must be logged in to logout everywhere).
     */
    @PostMapping("/logout-all")
    @Operation(
        summary = "Logout from all devices",
        description = "Revokes all active sessions and tokens for the authenticated user across all devices",
        security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ApiResponse<Void> logoutAll(
            @RequestHeader("Authorization") String authorizationHeader) {
        // Extract access token and user info
        String accessToken = authorizationHeader.substring(7); // Remove "Bearer "
        java.util.UUID userId = jwtService.extractUserId(accessToken);
        
        authService.logoutAll(userId, accessToken);
        return ApiResponse.success(null, "User logged out successfully from all devices");
    }
}

