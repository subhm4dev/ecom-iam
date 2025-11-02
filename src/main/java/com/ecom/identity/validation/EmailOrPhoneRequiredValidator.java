package com.ecom.identity.validation;

import com.ecom.identity.entity.UserAccount;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

/**
 * Validator for {@link EmailOrPhoneRequired} annotation.
 * Ensures that at least one of email or phone is provided (not null and not empty).
 */
public class EmailOrPhoneRequiredValidator implements ConstraintValidator<EmailOrPhoneRequired, UserAccount> {

    @Override
    public void initialize(EmailOrPhoneRequired constraintAnnotation) {
        // No initialization needed
    }

    @Override
    public boolean isValid(UserAccount userAccount, ConstraintValidatorContext context) {
        if (userAccount == null) {
            return true; // Let @NotNull handle null checks
        }

        String email = userAccount.getEmail();
        String phone = userAccount.getPhone();

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

