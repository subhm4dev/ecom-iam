package com.ecom.identity.service.impl;

import com.ecom.error.exception.BusinessException;
import com.ecom.error.model.ErrorCode;
import com.ecom.identity.entity.RoleGrant;
import com.ecom.identity.entity.Tenant;
import com.ecom.identity.entity.UserAccount;
import com.ecom.identity.model.request.LoginRequest;
import com.ecom.identity.model.request.RefreshRequest;
import com.ecom.identity.model.request.RegisterRequest;
import com.ecom.identity.model.response.LoginResponse;
import com.ecom.identity.model.response.RefreshResponse;
import com.ecom.identity.model.response.RegisterResponse;
import com.ecom.identity.entity.RefreshToken;
import com.ecom.identity.repository.RefreshTokenRepository;
import com.ecom.identity.repository.RoleGrantRepository;
import com.ecom.identity.repository.TenantRepository;
import com.ecom.identity.repository.UserAccountRepository;
import com.ecom.identity.service.AuthService;
import com.ecom.identity.service.JwtService;
import com.ecom.identity.service.PasswordService;
import com.ecom.identity.service.SessionService;
import com.ecom.identity.model.request.LogoutRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Authentication service implementation
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final UserAccountRepository userAccountRepository;
    private final TenantRepository tenantRepository;
    private final RoleGrantRepository roleGrantRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordService passwordService;
    private final JwtService jwtService;
    private final SessionService sessionService;

    @Value("${jwt.refresh-token.expiry-days:30}")
    private int refreshTokenExpiryDays;

    @Override
    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        // 1. Determine tenant based on role
        Tenant tenant;
        UUID tenantId = request.tenantId();

        if (tenantId != null) {
            // Tenant ID provided - validate it exists
            tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new BusinessException(ErrorCode.SKU_REQUIRED, "Invalid tenant ID"));
        } else {
            // Tenant ID not provided - auto-assign based on role
            if (request.role() == com.ecom.identity.constants.Role.CUSTOMER) {
                // Customers → Default marketplace tenant
                UUID defaultMarketplaceTenantId = UUID.fromString("00000000-0000-0000-0000-000000000000");
                tenant = tenantRepository.findById(defaultMarketplaceTenantId)
                    .orElseThrow(() -> new BusinessException(ErrorCode.SKU_REQUIRED,
                        "Default marketplace tenant not found. Please run database migrations."));
            } else if (request.role() == com.ecom.identity.constants.Role.SELLER) {
                // Sellers → Create new tenant
                tenant = Tenant.builder()
                    .name("Seller: " + (request.email() != null ? request.email() : request.phone()))
                    .status(com.ecom.identity.constants.TenantStatus.ACTIVE)
                    .build();
                tenant = tenantRepository.save(tenant);
            } else {
                // Other roles require explicit tenant ID
                throw new BusinessException(ErrorCode.SKU_REQUIRED,
                    "Tenant ID is required for role: " + request.role());
            }
        }

        tenantId = tenant.getId(); // Use resolved tenant ID for subsequent checks

        // 2. Check email uniqueness within tenant scope
        if (request.email() != null && !request.email().isBlank()) {
            UUID finalTenantId = tenantId;
            userAccountRepository.findByEmail(request.email())
                .ifPresent(existing -> {
                    // Check if same tenant (tenant-scoped uniqueness)
                    if (existing.getTenant().getId().equals(finalTenantId)) {
                        throw new BusinessException(ErrorCode.EMAIL_TAKEN, "Email already registered");
                    }
                });
        }

        // 3. Check phone uniqueness within tenant scope
        if (request.phone() != null && !request.phone().isBlank()) {
            UUID finalTenantId1 = tenantId;
            userAccountRepository.findByPhone(request.phone())
                .ifPresent(existing -> {
                    // Check if same tenant (tenant-scoped uniqueness)
                    if (existing.getTenant().getId().equals(finalTenantId1)) {
                        throw new BusinessException(ErrorCode.PHONE_TAKEN, "Phone already registered");
                    }
                });
        }

        // 4. Generate salt and hash password
        String salt = passwordService.generateSalt();
        String passwordHash = passwordService.hashPassword(request.password(), salt);

        // 5. Create UserAccount entity
        UserAccount userAccount = UserAccount.builder()
            .email(request.email())
            .phone(request.phone())
            .passwordHash(passwordHash)
            .salt(salt)
            .tenant(tenant)
            .enabled(true)
            .emailVerified(false)
            .phoneVerified(false)
            .build();

        // 6. Persist UserAccount
        userAccount = userAccountRepository.save(userAccount);

        // 7. Create and persist RoleGrant
        RoleGrant roleGrant = RoleGrant.builder()
            .user(userAccount)
            .role(request.role())
            .build();
        roleGrantRepository.save(roleGrant);

        // 8. Generate tokens for auto-login
        List<String> roles = List.of(roleGrant.getRole().name());
        String accessToken = jwtService.generateAccessToken(userAccount, roles);

        // 9. Generate and store refresh token
        String refreshTokenString = jwtService.generateRefreshTokenString();
        String refreshTokenHash = passwordService.hashTokenDeterministically(refreshTokenString);
        LocalDateTime refreshTokenExpiresAt = LocalDateTime.now().plusDays(refreshTokenExpiryDays);

        RefreshToken refreshToken = RefreshToken.builder()
            .user(userAccount)
            .tokenHash(refreshTokenHash)
            .expiresAt(refreshTokenExpiresAt)
            .revoked(false)
            .build();
        refreshTokenRepository.save(refreshToken);

        // 10. Return response with access token
        return new RegisterResponse(
            accessToken,
            refreshTokenString, // Return plain refresh token (client stores this), not the hash
            userAccount.getId().toString(),
            roles,
            userAccount.getTenant().getId().toString()
        );
    }

    @Override
    @Transactional
    public LoginResponse login(LoginRequest request) {
        // 1. Find user by email or phone
        UserAccount userAccount = null;
        if (request.email() != null && !request.email().isBlank()) {
            userAccount = userAccountRepository.findByEmail(request.email())
                .orElseThrow(() -> new BusinessException(ErrorCode.BAD_CREDENTIALS, "Invalid email or password"));
        } else if (request.phone() != null && !request.phone().isBlank()) {
            userAccount = userAccountRepository.findByPhone(request.phone())
                .orElseThrow(() -> new BusinessException(ErrorCode.BAD_CREDENTIALS, "Invalid phone or password"));
        } else {
            throw new BusinessException(ErrorCode.BAD_CREDENTIALS, "Email or phone is required");
        }

        // 2. Check if user is enabled
        if (!userAccount.isEnabled()) {
            throw new BusinessException(ErrorCode.BAD_CREDENTIALS, "User account is disabled");
        }

        // 3. Verify password
        boolean passwordMatches = passwordService.verifyPassword(
            request.password(),
            userAccount.getPasswordHash(),
            userAccount.getSalt()
        );

        if (!passwordMatches) {
            throw new BusinessException(ErrorCode.BAD_CREDENTIALS, "Invalid email or password");
        }

        // 4. Load user roles from RoleGrant repository
        List<RoleGrant> roleGrants = roleGrantRepository.findAllByUser(userAccount);
        List<String> roles = roleGrants.stream()
            .map(roleGrant -> roleGrant.getRole().name())
            .toList();

        // 5. Generate access token (2 hours expiry)
        String accessToken = jwtService.generateAccessToken(userAccount, roles);

        // 6. Generate and store refresh token
        String refreshTokenString = jwtService.generateRefreshTokenString();
        String refreshTokenHash = passwordService.hashTokenDeterministically(refreshTokenString);
        LocalDateTime refreshTokenExpiresAt = LocalDateTime.now().plusDays(refreshTokenExpiryDays);

        RefreshToken refreshToken = RefreshToken.builder()
            .user(userAccount)
            .tokenHash(refreshTokenHash)
            .expiresAt(refreshTokenExpiresAt)
            .revoked(false)
            .build();
        refreshTokenRepository.save(refreshToken);

        // 7. Calculate access token expiry in seconds (get from JwtService config)
        // Note: JwtService uses accessTokenExpiryHours config value
        long expiresInSeconds = 2L * 3600L; // 2 hours (should match JwtService config)

        // 8. Return LoginResponse with tokens
        return new LoginResponse(
            accessToken,
            refreshTokenString, // Return plain refresh token (client stores this)
            expiresInSeconds,
            userAccount.getId().toString(),
            roles,
            userAccount.getTenant().getId().toString()
        );
    }

    @Override
    @Transactional
    public RefreshResponse refresh(RefreshRequest request, String accessToken) {
        // 1. Hash the refresh token to lookup in database
        String refreshTokenHash = passwordService.hashTokenDeterministically(request.refreshToken());

        // 2. Find refresh token in database
        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(refreshTokenHash)
            .orElseThrow(() -> new BusinessException(ErrorCode.BAD_CREDENTIALS, "Invalid refresh token"));

        // 3. Check if token is revoked
        if (refreshToken.isRevoked()) {
            throw new BusinessException(ErrorCode.BAD_CREDENTIALS, "Refresh token has been revoked");
        }

        // 4. Check if token is expired
        if (refreshToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new BusinessException(ErrorCode.BAD_CREDENTIALS, "Refresh token has expired");
        }

        // 5. Get user account and check if enabled
        UserAccount userAccount = refreshToken.getUser();
        if (!userAccount.isEnabled()) {
            throw new BusinessException(ErrorCode.BAD_CREDENTIALS, "User account is disabled");
        }

        // 6. If access token is provided, validate it belongs to the same user
        // This adds an extra security layer: even if refresh token is valid,
        // the access token must belong to the same user
        if (accessToken != null && !accessToken.isBlank()) {
            try {
                UUID accessTokenUserId = jwtService.extractUserId(accessToken);
                if (!accessTokenUserId.equals(userAccount.getId())) {
                    throw new BusinessException(ErrorCode.BAD_CREDENTIALS, "Refresh token and access token belong to different users");
                }
            } catch (Exception e) {
                // Access token may be expired or invalid - that's okay for refresh
                // We'll proceed with refresh token validation only
                log.debug("Could not validate access token during refresh (may be expired): {}", e.getMessage());
            }
        }

        // 7. Load user roles
        List<RoleGrant> roleGrants = roleGrantRepository.findAllByUser(userAccount);
        List<String> roles = roleGrants.stream()
            .map(roleGrant -> roleGrant.getRole().name())
            .toList();

        // 8. Generate new access token
        String newAccessToken = jwtService.generateAccessToken(userAccount, roles);

        // 9. Calculate access token expiry in seconds (2 hours = 7200 seconds)
        long expiresInSeconds = 2L * 3600L; // 2 hours

        // 10. Return RefreshResponse with new access token
        return new RefreshResponse(newAccessToken, expiresInSeconds);
    }

    @Override
    @Transactional
    public void logout(LogoutRequest logoutRequest, String accessToken) {
        // 1. Validate access token is provided (required for authentication)
        if (accessToken == null || accessToken.isBlank()) {
            throw new BusinessException(ErrorCode.BAD_CREDENTIALS, "Access token is required for logout");
        }

        // 2. Extract user ID from access token
        UUID authenticatedUserId;
        try {
            authenticatedUserId = jwtService.extractUserId(accessToken);
        } catch (Exception e) {
            throw new BusinessException(ErrorCode.BAD_CREDENTIALS, "Invalid or expired access token");
        }

        // 3. Hash the refresh token to lookup in database
        String refreshTokenHash = passwordService.hashTokenDeterministically(logoutRequest.refreshToken());

        // 4. Find refresh token
        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(refreshTokenHash)
            .orElseThrow(() -> new BusinessException(ErrorCode.BAD_CREDENTIALS, "Invalid refresh token"));

        // 5. Validate refresh token belongs to the authenticated user (security check)
        UUID refreshTokenUserId = refreshToken.getUser().getId();
        if (!refreshTokenUserId.equals(authenticatedUserId)) {
            throw new BusinessException(ErrorCode.BAD_CREDENTIALS, "Refresh token does not belong to authenticated user");
        }

        // 6. Check if refresh token is already revoked
        if (refreshToken.isRevoked()) {
            throw new BusinessException(ErrorCode.BAD_CREDENTIALS, "Refresh token already revoked");
        }

        // 7. Revoke the refresh token
        refreshToken.setRevoked(true);
        refreshTokenRepository.save(refreshToken);

        // 8. Blacklist the access token
        String tokenId = jwtService.extractTokenId(accessToken);
        long expiresInSeconds = jwtService.getTokenExpirySeconds(accessToken);
        sessionService.blacklistToken(tokenId, expiresInSeconds);

        log.info("User logged out: userId={}", authenticatedUserId);
    }

    @Override
    @Transactional
    public void logoutAll(UUID userId, String accessToken) {
        // 1. Revoke all refresh tokens for this user
        List<RefreshToken> userRefreshTokens = refreshTokenRepository.findByUser_IdAndRevokedFalse(userId);
        userRefreshTokens.forEach(token -> {
            token.setRevoked(true);
            refreshTokenRepository.save(token);
        });

        // 2. Revoke all sessions in Redis (blacklist all access tokens)
        sessionService.revokeAllUserSessions(userId);

        // 3. Also blacklist the current access token if provided
        if (accessToken != null && !accessToken.isBlank()) {
            String tokenId = jwtService.extractTokenId(accessToken);
            long expiresInSeconds = jwtService.getTokenExpirySeconds(accessToken);
            sessionService.blacklistToken(tokenId, expiresInSeconds);
        }

        log.info("User logged out from all devices: userId={}, sessions={}", userId, userRefreshTokens.size());
    }
}
