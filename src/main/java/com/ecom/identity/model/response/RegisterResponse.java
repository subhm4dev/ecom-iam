package com.ecom.identity.model.response;

import java.util.List;
import java.util.UUID;

/**
 * Registration response DTO
 */
public record RegisterResponse(
    String token,
    String refreshToken,
    String id,
    List<String> role,
    String tenantId
) {
}
