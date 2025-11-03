package com.ecom.identity.model.request;

import com.ecom.identity.constants.Role;
import com.ecom.identity.validation.EmailOrPhoneRequired;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.UUID;

/**
 * Registration request DTO
 * 
 * <p>Supports registration with either email OR phone (at least one required).
 * Password and role are mandatory fields.
 * 
 * <p>Tenant ID behavior:
 * <ul>
 *   <li><b>CUSTOMER:</b> tenantId is optional. If not provided, user is auto-assigned to default marketplace tenant.</li>
 *   <li><b>SELLER:</b> tenantId is optional. If not provided, a new tenant is created for the seller.</li>
 *   <li><b>Other roles:</b> tenantId may be required based on business logic.</li>
 * </ul>
 */
@EmailOrPhoneRequired
public record RegisterRequest(
    @Email(message = "Email must be valid format")
    String email,
    
    @Pattern(regexp = "^\\+[1-9]\\d{1,14}$", message = "Phone must be in E.164 format (e.g., +919876543210)")
    String phone,
    
    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    String password,
    
    // Tenant ID is optional - will be auto-assigned for customers, auto-created for sellers
    UUID tenantId,
    
    @NotNull(message = "Role is required")
    Role role
) {
}
