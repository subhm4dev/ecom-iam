package com.ecom.identity.validation;

import com.ecom.identity.entity.UserAccount;
import com.ecom.identity.model.request.LoginRequest;
import com.ecom.identity.model.request.RegisterRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

/**
 * Validator for {@link EmailOrPhoneRequired} annotation.
 * Ensures that at least one of email or phone is provided (not null and not empty).
 * 
 * Supports validation for:
 * - UserAccount (entity)
 * - RegisterRequest (DTO)
 * - LoginRequest (DTO)
 */
public class EmailOrPhoneRequiredValidator implements ConstraintValidator<EmailOrPhoneRequired, Object> {

    @Override
    public void initialize(EmailOrPhoneRequired constraintAnnotation) {
        // No initialization needed
    }

    @Override
    public boolean isValid(Object obj, ConstraintValidatorContext context) {
        if (obj == null) {
            return true; // Let @NotNull handle null checks
        }

        String email = null;
        String phone = null;

        // Extract email and phone based on object type
        if (obj instanceof UserAccount userAccount) {
            email = userAccount.getEmail();
            phone = userAccount.getPhone();
        } else if (obj instanceof RegisterRequest registerRequest) {
            email = registerRequest.email();
            phone = registerRequest.phone();
        } else if (obj instanceof LoginRequest loginRequest) {
            email = loginRequest.email();
            phone = loginRequest.phone();
        } else {
            // Unknown type - fail validation
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(
                "EmailOrPhoneRequired validation is only supported for UserAccount, RegisterRequest, or LoginRequest"
            ).addConstraintViolation();
            return false;
        }

        boolean hasEmail = email != null && !email.trim().isEmpty();
        boolean hasPhone = phone != null && !phone.trim().isEmpty();

        boolean isValid = hasEmail || hasPhone;

        if (!isValid) {
            // Customize the constraint violation message
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(
                "Either email or phone must be provided"
            ).addConstraintViolation();
        }

        return isValid;
    }
}

