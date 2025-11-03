package com.ecom.identity.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI Configuration
 * 
 * <p>Configures OpenAPI/Swagger documentation with bearer token authentication.
 * This enables the "lock" icon in Swagger UI where users can input their JWT token
 * for testing protected endpoints.
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .components(new Components()
                .addSecuritySchemes("bearerAuth", 
                    new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")
                        .description("JWT token obtained from /api/v1/auth/login endpoint. " +
                                   "Prefix token with 'Bearer ' when using in Authorization header.")));
    }
}

