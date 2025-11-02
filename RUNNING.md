# Running the Identity Service

## Prerequisites
- Java 25
- PostgreSQL 18+ running on `localhost:5432`
- Database `ecom_iam` created

## Running with Maven

### Using Spring Boot Maven Plugin (Recommended)
```bash
mvn spring-boot:run
```
The JVM arguments are automatically configured in `pom.xml`.

### Running JAR directly
```bash
mvn clean package
java --enable-native-access=ALL-UNNAMED -jar target/identity-0.1.0-SNAPSHOT.jar
```

## Running in IDE (IntelliJ IDEA / VS Code)

### IntelliJ IDEA
1. Go to **Run** → **Edit Configurations**
2. Find your `IdentityApplication` run configuration
3. In **VM options**, add:
   ```
   --enable-native-access=ALL-UNNAMED
   ```

### VS Code (Java Extension)
Add to `.vscode/settings.json`:
```json
{
  "java.configuration.runtimes": [
    {
      "name": "JavaSE-25",
      "path": "/path/to/java25",
      "default": true
    }
  ],
  "java.debug.settings.vmArgs": "--enable-native-access=ALL-UNNAMED"
}
```

## About the Native Access Warning

The warning `java.lang.System::load has been called` appears because:
- `argon2-jvm` uses JNA (Java Native Access) to load native Argon2 libraries
- Java 17+ restricts native library loading for security
- The `--enable-native-access=ALL-UNNAMED` flag grants permission

**This is safe** - we're explicitly allowing native access for the Argon2 library, which is a legitimate use case for cryptographic operations.

## Environment Variables

Set before running:
```bash
export PASSWORD_PEPPER="your-64-byte-random-pepper-here"
export GITHUB_TOKEN="your-github-token"  # For Maven dependencies
```

