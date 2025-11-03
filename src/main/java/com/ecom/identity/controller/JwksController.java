package com.ecom.identity.controller;

import com.ecom.identity.service.JwksService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * JWKS (JSON Web Key Set) Controller
 * 
 * <p>This controller exposes public RSA keys used for JWT verification in the
 * standard JWKS format. The Gateway service uses this endpoint to validate
 * JWT tokens issued by the Identity service.
 * 
 * <p>Why we need this API:
 * <ul>
 *   <li><b>JWT Verification:</b> Gateway needs public keys to verify JWT signatures
 *       without contacting the Identity service for every request. This follows
 *       the standard OAuth2/OIDC JWKS pattern.</li>
 *   <li><b>Key Rotation:</b> Supports multiple active keys (via 'kid' parameter)
 *       enabling seamless key rotation without service downtime.</li>
 *   <li><b>Standard Protocol:</b> Follows RFC 7517 JWKS specification, making it
 *       compatible with standard OAuth2 libraries and tools.</li>
 * </ul>
 * 
 * <p>This endpoint is public (no authentication required) as it only exposes
 * public keys. The private keys remain secure in the Identity service database.
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "JWKS", description = "JSON Web Key Set endpoint for JWT verification")
public class JwksController {

    private final JwksService jwksService;

    /**
     * Get JSON Web Key Set (JWKS)
     * 
     * <p>Returns the public keys used for JWT signing in JWKS format. The Gateway
     * periodically fetches this endpoint to get the latest public keys for token
     * verification.
     * 
     * <p>The response follows RFC 7517 format:
     * <pre>
     * {
     *   "keys": [
     *     {
     *       "kty": "RSA",
     *       "kid": "key-1",
     *       "use": "sig",
     *       "alg": "RS256",
     *       "n": "...",
     *       "e": "AQAB"
     *     }
     *   ]
     * }
     * </pre>
     * 
     * <p>Gateway caches these keys and refreshes periodically to support key rotation.
     */
    @GetMapping("/.well-known/jwks.json")
    @Operation(
        summary = "Get JSON Web Key Set",
        description = "Returns public RSA keys for JWT signature verification in standard JWKS format",
        security = {}
    )
    public ResponseEntity<Map<String, Object>> getJwks() {
        Map<String, Object> jwks = jwksService.getJwks();
        return ResponseEntity.ok(jwks);
    }
}

