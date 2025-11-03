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
        // 1. Validate tenant exists
        Tenant tenant = tenantRepository.findById(request.tenantId())
            .orElseThrow(() -> new BusinessException(ErrorCode.SKU_REQUIRED, "Invalid tenant ID"));

        // 2. Check email uniqueness within tenant scope
        if (request.email() != null && !request.email().isBlank()) {
            userAccountRepository.findByEmail(request.email())
                .ifPresent(existing -> {
                    // Check if same tenant (tenant-scoped uniqueness)
                    if (existing.getTenant().getId().equals(request.tenantId())) {
                        throw new BusinessException(ErrorCode.EMAIL_TAKEN, "Email already registered");
                    }
                });
        }

        // 3. Check phone uniqueness within tenant scope
        if (request.phone() != null && !request.phone().isBlank()) {
            userAccountRepository.findByPhone(request.phone())
                .ifPresent(existing -> {
                    // Check if same tenant (tenant-scoped uniqueness)
                    if (existing.getTenant().getId().equals(request.tenantId())) {
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
    public RefreshResponse refresh(RefreshRequest request) {
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

        // 6. Load user roles
        List<RoleGrant> roleGrants = roleGrantRepository.findAllByUser(userAccount);
        List<String> roles = roleGrants.stream()
            .map(roleGrant -> roleGrant.getRole().name())
            .toList();

        // 7. Generate new access token
        String newAccessToken = jwtService.generateAccessToken(userAccount, roles);

        // 8. Calculate access token expiry in seconds (2 hours = 7200 seconds)
        long expiresInSeconds = 2L * 3600L; // 2 hours

        // 9. Return RefreshResponse with new access token
        return new RefreshResponse(newAccessToken, expiresInSeconds);
    }

    @Override
    @Transactional
    public void logout(LogoutRequest logoutRequest, String accessToken) {
        // 1. Hash the refresh token to lookup in database
        String refreshTokenHash = passwordService.hashTokenDeterministically(logoutRequest.refreshToken());
        
        // 2. Find and revoke the refresh token
        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(refreshTokenHash)
            .orElseThrow(() -> new BusinessException(ErrorCode.BAD_CREDENTIALS, "Invalid refresh token"));
        
        if (refreshToken.isRevoked()) {
            throw new BusinessException(ErrorCode.BAD_CREDENTIALS, "Refresh token already revoked");
        }
        
        refreshToken.setRevoked(true);
        refreshTokenRepository.save(refreshToken);
        
        // 3. Blacklist the access token (if provided)
        if (accessToken != null && !accessToken.isBlank()) {
            String tokenId = jwtService.extractTokenId(accessToken);
            long expiresInSeconds = jwtService.getTokenExpirySeconds(accessToken);
            sessionService.blacklistToken(tokenId, expiresInSeconds);
        }
        
        log.info("User logged out: userId={}", refreshToken.getUser().getId());
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
