# IAM Service Implementation Plan

## Architecture Overview

The Identity service handles:
- User registration and authentication
- JWT token generation and refresh
- JWKS endpoint for public key distribution
- Argon2 password hashing
- Multi-tenant support

## Step-by-Step Implementation Guide

### Phase 1: Database Schema (Flyway Migrations)

**Step 1.1: Create First Migration**
- File: `src/main/resources/db/migration/`
- Create tables:
  1. `tenants` - Multi-tenant support
  2. `user_accounts` - User credentials and basic info
  3. `role_grants` - User roles (CUSTOMER, SELLER, ADMIN, etc.)
  4. `jwk_keys` - RSA key pairs for JWT signing
  5. `refresh_tokens` - Refresh token storage

**Step 1.2: Table Specifications**

1. **tenants**
   - `id` BIGINT PRIMARY KEY
   - `name` VARCHAR(255) NOT NULL
   - `created_at` TIMESTAMP
   - `updated_at` TIMESTAMP

2. **user_accounts**
   - `id` VARCHAR(255) PRIMARY KEY (e.g., "user-123")
   - `email` VARCHAR(255) UNIQUE (nullable - either email or phone required)
   - `phone` VARCHAR(20) UNIQUE (nullable - either email or phone required)
   - `password_hash` VARCHAR(255) NOT NULL (Argon2i hash)
   - `salt` VARCHAR(255) NOT NULL (explicit salt for salt+pepper technique)
   - `tenant_id` BIGINT NOT NULL REFERENCES tenants(id)
   - `enabled` BOOLEAN DEFAULT true
   - `email_verified` BOOLEAN DEFAULT false
   - `phone_verified` BOOLEAN DEFAULT false
   - `created_at` TIMESTAMP
   - `updated_at` TIMESTAMP
   - Index on `email`, `phone`, `tenant_id`
   - Check constraint: at least one of email or phone must be NOT NULL

3. **role_grants**
   - `id` BIGINT PRIMARY KEY (auto-generated)
   - `user_id` VARCHAR(255) NOT NULL REFERENCES user_accounts(id)
   - `role` VARCHAR(50) NOT NULL (CUSTOMER, SELLER, ADMIN, STAFF, DRIVER)
   - `granted_at` TIMESTAMP
   - Unique constraint on (user_id, role)

4. **jwk_keys**
   - `id` VARCHAR(255) PRIMARY KEY (e.g., "key-1")
   - `kid` VARCHAR(50) UNIQUE NOT NULL (Key ID for JWKS)
   - `public_key_pem` TEXT NOT NULL
   - `private_key_pem` TEXT NOT NULL
   - `algorithm` VARCHAR(50) DEFAULT 'RS256'
   - `created_at` TIMESTAMP
   - `expires_at` TIMESTAMP
   - Index on `kid`

5. **refresh_tokens**
   - `id` VARCHAR(255) PRIMARY KEY
   - `user_id` VARCHAR(255) NOT NULL REFERENCES user_accounts(id)
   - `token_hash` VARCHAR(255) NOT NULL (hash of refresh token)
   - `expires_at` TIMESTAMP NOT NULL
   - `revoked` BOOLEAN DEFAULT false
   - `created_at` TIMESTAMP
   - Index on `user_id`, `expires_at`

---

### Phase 2: JPA Entities

**Step 2.1: Create Entity Package Structure**
- Package: `com.ecom.identity.entity`
- Create entities: `Tenant`, `UserAccount`, `RoleGrant`, `JwkKey`, `RefreshToken`

**Step 2.2: Entity Requirements**
- Use `@Entity`, `@Table` annotations
- Use Lombok `@Getter`, `@Setter`, `@NoArgsConstructor`, `@AllArgsConstructor`
- Include `@CreatedDate`, `@LastModifiedDate` for audit fields (use Spring Data JPA auditing)
- Use UUID or string IDs (not auto-increment for user accounts)

---

### Phase 3: Repository Layer

**Step 3.1: Create Repositories**
- Package: `com.ecom.identity.repository`
- Create: `TenantRepository`, `UserAccountRepository`, `RoleGrantRepository`, `JwkKeyRepository`, `RefreshTokenRepository`
- Use Spring Data JPA (`JpaRepository<T, ID>`)
- Add custom query methods as needed:
  - `findByEmail(String email)` in UserAccountRepository
  - `findByPhone(String phone)` in UserAccountRepository
  - `findByEmailOrPhone(String email, String phone)` in UserAccountRepository (for login)
  - `findActiveKey()` in JwkKeyRepository

---

### Phase 4: Service Layer

**Step 4.1: Password Encoding Service (Salt + Pepper with Argon2i)**
- Package: `com.ecom.identity.service`
- Class: `PasswordService`
- **Architecture: Salt + Pepper Technique**
  - **Salt**: Random 32-byte value, unique per user, stored in `user_accounts.salt`
  - **Pepper**: Secret value from config/env (`${PASSWORD_PEPPER}`), same for all users, NOT stored in DB
  - **Algorithm**: Argon2i (constant-time variant, resistant to side-channel attacks)
  
- **Dependencies**:
  - `org.springframework.security:spring-security-crypto` (optional, for compatibility)
  - `de.mkammerer:argon2-jvm` (version 2.12) - Direct Argon2 library for explicit salt control
  - Java `SecureRandom` for salt generation
  - `java.util.Base64` for encoding salt/hash
  
- **Configuration** (in `application.yml`):
  ```yaml
  password:
    pepper: ${PASSWORD_PEPPER:change-this-in-production} # Read from env var
  argon2:
    salt-length: 32 # bytes
    hash-length: 32 # bytes
    parallelism: 1
    memory: 65536 # 64 MB
    iterations: 3
  ```

- **Methods**:
  - `generateSalt()` → Returns Base64-encoded random salt (32 bytes)
    ```java
    SecureRandom random = new SecureRandom();
    byte[] saltBytes = new byte[32]; // 32 bytes = 256 bits
    random.nextBytes(saltBytes);
    return Base64.getEncoder().encodeToString(saltBytes);
    ```
  
  - `encode(String password, String saltBase64, String pepper)` → Returns Base64-encoded Argon2i hash
    ```java
    import de.mkammerer.argon2.Argon2;
    import de.mkammerer.argon2.Argon2Factory;
    import de.mkammerer.argon2.Argon2Factory.Argon2Types;
    
    // Decode salt from Base64
    byte[] salt = Base64.getDecoder().decode(saltBase64);
    // Combine password + pepper
    String passwordWithPepper = password + pepper;
    // Create Argon2 instance (Argon2i variant)
    Argon2 argon2 = Argon2Factory.create(Argon2Types.ARGON2i);
    // Hash with explicit salt (returns raw hash bytes)
    byte[] hashBytes = argon2.rawHash(iterations, memory, parallelism,
                                      passwordWithPepper.toCharArray(), salt);
    // Clean up sensitive data
    argon2.wipeArray(passwordWithPepper.toCharArray());
    // Return Base64-encoded hash
    return Base64.getEncoder().encodeToString(hashBytes);
    ```
    **Note**: Using `rawHash()` method to get just the hash bytes (without formatting) since we store salt separately in the database.
  
  - `matches(String rawPassword, String storedHashBase64, String storedSaltBase64, String pepper)` → Validates password
    ```java
    import java.security.MessageDigest;
    
    // Hash input password with same salt and pepper
    byte[] computedHashBytes = Base64.getDecoder().decode(
        encode(rawPassword, storedSaltBase64, pepper)
    );
    byte[] storedHashBytes = Base64.getDecoder().decode(storedHashBase64);
    // Constant-time comparison (prevents timing attacks)
    return MessageDigest.isEqual(storedHashBytes, computedHashBytes);
    ```
    **Note**: We use `MessageDigest.isEqual()` instead of `Arrays.equals()` because it's constant-time, preventing timing attacks.
  
- **Hashing Flow**:
  1. Generate random salt (32 bytes) → Base64 encode → Store in DB
  2. Combine: `password + pepper` (pepper from config/env)
  3. Hash with Argon2i: `Argon2i(password + pepper, salt)`
  4. Store hash in `password_hash` column
  
- **Verification Flow**:
  1. Retrieve `password_hash` and `salt` from DB
  2. Get `pepper` from config/env
  3. Hash input: `Argon2i(inputPassword + pepper, salt)`
  4. Compare with stored `password_hash`
  
- **Security Benefits**:
  - **Salt**: Prevents rainbow table attacks (unique per user)
  - **Pepper**: Adds server-side secret (even if DB is compromised, attacker needs pepper)
  - **Argon2i**: Memory-hard function, resistant to GPU/ASIC attacks

**Step 4.2: JWT Service**
- Class: `JwtService`
- Dependencies: Need to add JWT library (Nimbus JOSE + JWT or io.jsonwebtoken)
- Methods:
  - `generateAccessToken(UserAccount, List<String> roles)` → Returns JWT string
  - `generateRefreshToken(UserAccount)` → Returns token string
  - `getActiveKeyPair()` → Returns RSA key pair for signing
  - `getPublicKey(String kid)` → For JWKS endpoint

**Step 4.3: JWKS Service**
- Class: `JwksService`
- Method: `getJwks()` → Returns JWKS JSON structure
- Should return active key(s) in JWKS format

**Step 4.4: Auth Service**
- Class: `AuthService`
- Methods:
  - `register(RegisterRequest)` → Returns RegisterResponse
    - Validate: either email or phone provided
    - Check: email unique OR phone unique (if provided)
    - Throw `EMAIL_TAKEN` or `PHONE_TAKEN` if duplicate
  - `login(LoginRequest)` → Returns LoginResponse (with tokens)
    - Accept email OR phone in request
    - Find user by email or phone
    - Verify password
  - `refresh(String refreshToken)` → Returns new access token
  - `logout(String refreshToken)` → Revokes refresh token

---

### Phase 5: DTOs (Request/Response)

**Step 5.1: Create DTOs**
- Package: `com.ecom.identity.dto`
- Request DTOs:
  - `RegisterRequest` (email OR phone, password, tenantId, role)
    - Either email or phone must be provided (not both, at least one)
  - `LoginRequest` (email OR phone, password)
    - User can login with either email or phone
  - `RefreshRequest` (refreshToken)
- Response DTOs:
  - `RegisterResponse` (userId, message)
  - `LoginResponse` (accessToken, refreshToken, expiresIn)
  - `RefreshResponse` (accessToken, expiresIn)

**Step 5.2: Validation**
- Use `@Valid`, `@NotNull`, `@Email`, `@Size`, `@Pattern` annotations
- Email: valid format if provided
- Phone: valid format if provided (e.g., E.164 format: +919876543210)
- Password: meet requirements (if any)
- Custom validation: ensure either email or phone is provided (but not both required)

---

### Phase 6: Controller Layer

**Step 6.1: Auth Controller**
- Package: `com.ecom.identity.controller`
- Class: `AuthController`
- Endpoints:
  - `POST /auth/register` → Register new user (with email OR phone)
  - `POST /auth/login` → Authenticate and get tokens (with email OR phone)
  - `POST /auth/refresh` → Refresh access token
  - `POST /auth/logout` → Logout (revoke refresh token)
  
**Note:** Registration and login support both email and phone number authentication

**Step 6.2: JWKS Controller**
- Class: `JwksController`
- Endpoint: `GET /.well-known/jwks.json` → Public keys for JWT verification

---

### Phase 7: Security Configuration

**Step 7.1: Security Config**
- Package: `com.ecom.identity.config`
- Class: `SecurityConfig`
- Requirements:
  - Permit all `/auth/**` endpoints (public)
  - Permit all `/.well-known/**` endpoints (public)
  - Secure all other endpoints (require authentication)
  - Disable CSRF (stateless JWT-based auth)
  - **Note**: We're using direct Argon2 library (`de.urner.argon2`) instead of Spring's `Argon2PasswordEncoder` for explicit salt+pepper control

---

### Phase 8: Key Management

**Step 8.1: Key Generation on Startup**
- Class: `JwkKeyInitializer` (implements `ApplicationListener<ApplicationReadyEvent>`)
- On application start:
  - Check if active JWT key exists in database
  - If not, generate RSA key pair (2048-bit)
  - Store in `jwk_keys` table
  - Set expiration (e.g., 90 days from now)

**Step 8.2: Key Rotation Strategy**
- Consider multiple active keys (one primary, others for rotation)
- Or single active key with renewal logic

---

### Phase 9: Error Handling

**Step 9.1: Custom Exceptions**
- Already have `BusinessException` from `custom-error-starter`
- Use `ErrorCode.EMAIL_TAKEN` for duplicate email
- Use `ErrorCode.BAD_CREDENTIALS` for wrong password
- Global exception handler already configured via starter

---

### Phase 10: Dependencies Check

**Step 10.1: Add JWT Library**
- Check `pom.xml` - need to add JWT dependency
- Options:
  - `io.jsonwebtoken:jjwt-api` + `jjwt-impl` + `jjwt-jackson` (0.12.x for Java 25)
  - OR `com.nimbusds:nimbus-jose-jwt` (more control)
- Recommend: Nimbus JOSE + JWT for better RSA key handling

**Step 10.2: Argon2 Dependency**
- Check if Argon2PasswordEncoder needs additional dependency
- Spring Security should have it, but may need `org.bouncycastle:bcprov-jdk18on`

---

## Implementation Order (What to Do When)

1. **First**: Create Flyway migration (V1) - This defines the database structure
2. **Second**: Create JPA entities matching the migration
3. **Third**: Create repositories
4. **Fourth**: Add JWT library dependency to pom.xml
5. **Fifth**: Create PasswordService with Argon2
6. **Sixth**: Create JWT key initialization logic
7. **Seventh**: Create JwtService for token generation
8. **Eighth**: Create AuthService with register/login logic
9. **Ninth**: Create DTOs
10. **Tenth**: Create controllers
11. **Eleventh**: Configure security
12. **Twelfth**: Create JWKS endpoint

---

## Testing Strategy

After implementation:
- Test registration with duplicate email → 409
- Test login with wrong password → 401
- Test login with correct credentials → 200 with tokens
- Test refresh token flow
- Test JWKS endpoint returns valid keys
- Integration tests with Testcontainers

---

## Notes

- User IDs: Use format like "user-123" (string, not UUID)
- Tenant ID 0: Represents the marketplace (default tenant)
- JWT expiration: Access token 15 minutes (900s), Refresh token 7 days
- Roles: CUSTOMER, SELLER, ADMIN, STAFF, DRIVER
- **Authentication**: Users can register and login with EITHER email OR phone number
- Phone format: Recommend E.164 format (e.g., +919876543210) for international support
- Duplicate check: Email must be unique if provided, phone must be unique if provided
- Verification: Store `email_verified` and `phone_verified` flags for future OTP verification feature

