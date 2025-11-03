package com.ecom.identity.model.request;

import com.ecom.identity.validation.EmailOrPhoneRequired;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Login request DTO
 * 
 * <p>Supports login with either email OR phone (at least one required).
 * Password is mandatory.
 */
@EmailOrPhoneRequired
public record LoginRequest(
    @Email(message = "Email must be valid format")
    String email,
    
    @Pattern(regexp = "^\\+[1-9]\\d{1,14}$", message = "Phone must be in E.164 format (e.g., +919876543210)")
    String phone,
    
    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    String password
) {
}

