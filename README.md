# 🔐 E-Commerce Identity Service

Identity and Access Management service for authentication and authorization.

## Features

- User registration and authentication
- JWT token generation
- JWKS endpoint for public key distribution
- Argon2 password hashing
- Multi-tenant support

## Endpoints

- `POST /auth/register` - Register new user
- `POST /auth/login` - User login
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - Logout
- `GET /.well-known/jwks.json` - Public keys for JWT verification

## Configuration

Configuration is pulled from Config Server (`ecom-config-repo`).

Database settings in `ecom-config-repo/identity-service/application.yml`.

## Running Locally

### Prerequisites
- Java 25
- Maven 3.9+
- PostgreSQL running (via `ecom-infrastructure`)
- Config Server running (port 8888) - optional, has fallback

### Run
```bash
mvn spring-boot:run
```

Identity service will start on port **8081**.

**Note:** The native access warning for JNA (used by Argon2) is automatically handled via JVM arguments in `pom.xml`. See `RUNNING.md` for IDE setup.

## Database

Uses Flyway for database migrations. Migration files go in `src/main/resources/db/migration/`.

## Development

Implement:
1. Entities: `Tenant`, `UserAccount`, `RoleGrant`, `JwkKey`, `RefreshToken`
2. Auth endpoints
3. JWKS endpoint
4. Integration tests with Testcontainers

