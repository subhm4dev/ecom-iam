package com.ecom.identity.model.response;

import java.util.List;

/**
 * Login response DTO
 */
public record LoginResponse(
    String accessToken,
    String refreshToken,
    Long expiresIn, // seconds until access token expires
    String id,
    List<String> role,
    String tenantId
) {
}

