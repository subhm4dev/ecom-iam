package com.ecom.identity.model.request;

import jakarta.validation.constraints.NotBlank;

/**
 * Refresh token request DTO
 */
public record RefreshRequest(
    @NotBlank(message = "Refresh token is required")
    String refreshToken
) {
}

