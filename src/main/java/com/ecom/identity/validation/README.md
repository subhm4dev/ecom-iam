# Custom Validation: EmailOrPhoneRequired

## Overview
The `@EmailOrPhoneRequired` annotation ensures that at least one of `email` or `phone` fields is provided (not null and not empty) when saving a `UserAccount` entity.

## Usage

### Entity Level
The annotation is already applied to the `UserAccount` entity:
```java
@Entity
@EmailOrPhoneRequired
public class UserAccount {
    private String email;
    private String phone;
    // ...
}
```

### Controller Level (Recommended)
Use `@Valid` in your controller methods to trigger validation:

```java
@PostMapping("/auth/register")
public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
    // Validation will trigger automatically
    // If both email and phone are null/empty, MethodArgumentNotValidException will be thrown
    // This is handled by GlobalExceptionHandler from custom-error-starter
}
```

### Service Level
You can also validate programmatically in your service:

```java
@Service
public class AuthService {
    
    @Autowired
    private Validator validator;
    
    public void register(UserAccount account) {
        Set<ConstraintViolation<UserAccount>> violations = validator.validate(account);
        if (!violations.isEmpty()) {
            throw new ConstraintViolationException(violations);
        }
        // Save account
    }
}
```

## Validation Behavior
- ✅ Valid: `email="user@example.com"`, `phone=null`
- ✅ Valid: `email=null`, `phone="+1234567890"`
- ✅ Valid: `email="user@example.com"`, `phone="+1234567890"`
- ❌ Invalid: `email=null`, `phone=null`
- ❌ Invalid: `email=""`, `phone=""` (empty strings are trimmed)

## Error Response
When validation fails, the `GlobalExceptionHandler` (from `custom-error-starter`) will return:
```json
{
  "error": "VALIDATION_ERROR",
  "message": "Either email or phone must be provided"
}
```

