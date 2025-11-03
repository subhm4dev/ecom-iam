package com.ecom.identity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security Configuration
 * 
 * <p>Configures security for the Identity service:
 * <ul>
 *   <li>Public endpoints: /api/v1/auth/** (register, login, refresh) and /.well-known/** (JWKS)</li>
 *   <li>Protected endpoints: All other endpoints require authentication</li>
 *   <li>Stateless: No session creation (JWT-based authentication)</li>
 *   <li>CSRF disabled: Stateless JWT auth doesn't need CSRF protection</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF (stateless JWT authentication)
            .csrf(AbstractHttpConfigurer::disable)
            
            // Stateless session management (JWT-based, no sessions)
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            
            // Configure endpoint access
            .authorizeHttpRequests(auth -> auth
                // Public endpoints (no authentication required)
                .requestMatchers(
                    "/api/v1/auth/**",  // All auth endpoints (register, login, refresh, logout)
                    "/.well-known/**",  // JWKS endpoint
                    "/actuator/health",
                    "/actuator/info",
                    "/swagger-ui/**",
                    "/v3/api-docs/**"
                ).permitAll()
                
                // All other endpoints require authentication
                .anyRequest().authenticated()
            );
        
        return http.build();
    }
}

