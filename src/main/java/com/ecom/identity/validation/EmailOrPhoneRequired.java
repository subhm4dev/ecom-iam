package com.ecom.identity.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

/**
 * Custom validation annotation to ensure that either email or phone (or both) is provided.
 * At least one of these fields must not be null or empty.
 */
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = EmailOrPhoneRequiredValidator.class)
@Documented
public @interface EmailOrPhoneRequired {
    
    String message() default "Either email or phone must be provided";
    
    Class<?>[] groups() default {};
    
    Class<? extends Payload>[] payload() default {};
}

