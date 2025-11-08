package com.ecom.identity.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Cookie Service for managing authentication cookies
 * 
 * <p><b>WHAT THIS DOES:</b>
 * This service handles setting and clearing HTTP-only cookies that store authentication tokens.
 * Cookies are a more secure way to store tokens compared to localStorage because they cannot
 * be accessed by JavaScript (protecting against XSS attacks).
 * 
 * <p><b>HOW IT WORKS:</b>
 * 1. When a user logs in/registers/refreshes, we set two cookies:
 *    - `accessToken`: Short-lived token (2 hours) for API authentication
 *    - `refreshToken`: Long-lived token (30 days) for getting new access tokens
 * 
 * 2. These cookies are:
 *    - HttpOnly: Cannot be read by JavaScript (XSS protection)
 *    - Secure: Only sent over HTTPS (in production)
 *    - SameSite: Prevents CSRF attacks
 * 
 * 3. When user logs out, we clear these cookies
 * 
 * <p><b>WHY WE NEED THIS:</b>
 * - <b>Security:</b> HttpOnly cookies protect tokens from XSS attacks (malicious JavaScript can't steal them)
 * - <b>Web Apps:</b> Browsers automatically send cookies with requests (no manual header management)
 * - <b>Mobile Apps:</b> Mobile apps don't use cookies (they use Keychain/Keystore), but this doesn't break them
 * - <b>Hybrid Approach:</b> Web uses cookies, mobile uses secure storage - both send tokens via Authorization header
 * 
 * <p><b>REAL-WORLD SCENARIOS THIS HANDLES:</b>
 * 
 * <b>Scenario 1: User logs in on web browser</b>
 * - User enters email/password and clicks "Login"
 * - Backend validates credentials and generates tokens
 * - Backend sets cookies in response (browser automatically stores them)
 * - Next time user visits the site, browser automatically sends cookies
 * - Gateway reads cookies and validates tokens
 * - User stays logged in for 30 days (refresh token lifetime)
 * 
 * <b>Scenario 2: User logs in on mobile app</b>
 * - Mobile app doesn't use cookies (no browser)
 * - App receives tokens in response body (same API)
 * - App stores tokens in Keychain (iOS) or Keystore (Android)
 * - App sends tokens via Authorization header (same as before)
 * - No breaking changes - mobile apps work exactly as before
 * 
 * <b>Scenario 3: User logs out</b>
 * - User clicks "Logout" button
 * - Backend revokes refresh token in database
 * - Backend clears cookies (sets them to expire immediately)
 * - Browser removes cookies automatically
 * - User is logged out immediately
 * 
 * <b>Scenario 4: Running locally (localhost:3000 → localhost:8081)</b>
 * - Cookies work fine on localhost
 * - Secure flag is false (allows HTTP for development)
 * - SameSite is Lax (works for same-origin requests)
 * - No domain set (browser handles localhost automatically)
 * 
 * <b>Scenario 5: Running in Kubernetes (api.example.com → frontend.example.com)</b>
 * - Cookies work across subdomains if domain is set (e.g., .example.com)
 * - Secure flag is true (requires HTTPS)
 * - SameSite might be None if needed for cross-domain (requires Secure=true)
 * - Domain is set from configuration (e.g., .example.com)
 * 
 * <b>Scenario 6: Token refresh</b>
 * - Access token expires after 2 hours
 * - Frontend calls refresh endpoint with refresh token (from cookie)
 * - Backend validates refresh token and issues new access token
 * - Backend sets new access token cookie (refresh token cookie remains)
 * - User continues using the app without re-login
 * 
 * <b>Scenario 7: XSS attack attempt</b>
 * - Attacker injects malicious JavaScript: `document.cookie`
 * - JavaScript tries to read cookies to steal tokens
 * - HttpOnly flag prevents JavaScript from accessing cookies
 * - Tokens remain safe even if XSS vulnerability exists
 * - This is why cookies are more secure than localStorage
 * 
 * <b>Scenario 8: CSRF attack attempt</b>
 * - Attacker's website tries to make request to our API
 * - Browser sends cookies automatically (SameSite protection)
 * - SameSite=Lax prevents cookies from being sent in cross-site POST requests
 * - CSRF attack fails (cookies not sent, request rejected)
 * 
 * <p><b>COOKIE CONFIGURATION:</b>
 * - <b>HttpOnly:</b> Always true (prevents JavaScript access)
 * - <b>Secure:</b> true in production (HTTPS only), false in development (allows HTTP)
 * - <b>SameSite:</b> Lax for same-site, None for cross-site (requires Secure=true)
 * - <b>Domain:</b> null for localhost, configured domain for production (e.g., .example.com)
 * - <b>Path:</b> / (entire domain)
 * - <b>MaxAge:</b> Based on token expiry (access token: 2 hours, refresh token: 30 days)
 */
@Service
public class CookieService {

    // Cookie names - these are the keys browsers use to store/retrieve cookies
    private static final String ACCESS_TOKEN_COOKIE_NAME = "accessToken";
    private static final String REFRESH_TOKEN_COOKIE_NAME = "refreshToken";

    // Cookie path - "/" means cookies are available for entire domain
    private static final String COOKIE_PATH = "/";

    // Whether we're in production (affects Secure flag)
    @Value("${app.environment:development}")
    private String environment;

    // Cookie domain for production (e.g., ".example.com" for all subdomains)
    // null means browser will use current domain (works for localhost)
    @Value("${app.cookie.domain:}")
    private String cookieDomain;

    // Whether to use SameSite=None (for cross-domain scenarios)
    // Only needed if frontend and backend are on different domains
    @Value("${app.cookie.same-site-none:false}")
    private boolean sameSiteNone;

    /**
     * Set authentication cookies in HTTP response
     * 
     * <p><b>WHAT THIS DOES:</b>
     * Creates two cookies (access token and refresh token) and adds them to the HTTP response.
     * The browser will automatically store these cookies and send them with future requests.
     * 
     * <p><b>HOW IT WORKS:</b>
     * 1. Creates access token cookie with 2-hour expiry
     * 2. Creates refresh token cookie with 30-day expiry
    3. Sets security flags (HttpOnly, Secure, SameSite)
     * 4. Adds cookies to response headers
     * 
     * <p><b>WHY WE NEED THIS:</b>
     * - Browsers automatically send cookies with requests (no manual header management)
     * - HttpOnly flag prevents JavaScript from stealing tokens (XSS protection)
     * - Secure flag ensures cookies only sent over HTTPS (production security)
     * 
     * <p><b>REAL-WORLD SCENARIO:</b>
     * User logs in → Backend calls this method → Cookies set in response → 
     * Browser stores cookies → Next API call automatically includes cookies → 
     * Gateway reads cookies and validates → User is authenticated
     * 
     * @param response HTTP response object (we add cookies to this)
     * @param accessToken JWT access token (short-lived, 2 hours)
     * @param refreshToken Refresh token string (long-lived, 30 days)
     * @param accessTokenExpirySeconds How long until access token expires (for cookie MaxAge)
     * @param refreshTokenExpiryDays How long until refresh token expires (for cookie MaxAge)
     */
    public void setAuthCookies(
            HttpServletResponse response,
            String accessToken,
            String refreshToken,
            long accessTokenExpirySeconds,
            int refreshTokenExpiryDays) {
        
        // Determine if we're in production (affects Secure flag)
        boolean isProduction = "production".equalsIgnoreCase(environment);
        
        // Determine SameSite value
        // - Lax: Cookies sent in same-site requests and top-level navigation (default, secure)
        // - None: Cookies sent in cross-site requests (requires Secure=true, for cross-domain)
        String sameSiteValue = sameSiteNone && isProduction ? "None" : "Lax";
        
        // Create access token cookie
        // WHAT: Stores the JWT access token
        // HOW: HttpOnly cookie (JavaScript can't access it)
        // WHY: More secure than localStorage (XSS protection)
        // REAL-WORLD: User logs in → Cookie set → Browser sends it automatically → Gateway validates
        Cookie accessTokenCookie = new Cookie(ACCESS_TOKEN_COOKIE_NAME, accessToken);
        accessTokenCookie.setHttpOnly(true); // JavaScript cannot access (XSS protection)
        accessTokenCookie.setSecure(isProduction); // HTTPS only in production, HTTP allowed in dev
        accessTokenCookie.setPath(COOKIE_PATH); // Available for entire domain
        accessTokenCookie.setMaxAge((int) accessTokenExpirySeconds); // Expires when token expires (2 hours)
        
        // Set domain if configured (for production cross-subdomain support)
        // null/empty = current domain (works for localhost)
        // ".example.com" = all subdomains (api.example.com, www.example.com share cookies)
        if (cookieDomain != null && !cookieDomain.isEmpty()) {
            accessTokenCookie.setDomain(cookieDomain);
        }
        
        // Set SameSite attribute (CSRF protection)
        // Lax: Default, secure, cookies sent in same-site requests
        // None: For cross-domain (requires Secure=true)
        accessTokenCookie.setAttribute("SameSite", sameSiteValue);
        
        // Create refresh token cookie (same configuration, longer expiry)
        Cookie refreshTokenCookie = new Cookie(REFRESH_TOKEN_COOKIE_NAME, refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(isProduction);
        refreshTokenCookie.setPath(COOKIE_PATH);
        refreshTokenCookie.setMaxAge((int) (refreshTokenExpiryDays * 24L * 3600L)); // Convert days to seconds
        
        if (cookieDomain != null && !cookieDomain.isEmpty()) {
            refreshTokenCookie.setDomain(cookieDomain);
        }
        
        refreshTokenCookie.setAttribute("SameSite", sameSiteValue);
        
        // Add cookies to response
        // Browser will automatically store these and send them with future requests
        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);
    }

    /**
     * Clear authentication cookies (logout)
     * 
     * <p><b>WHAT THIS DOES:</b>
     * Removes authentication cookies by setting them to expire immediately.
     * Browser will delete these cookies automatically.
     * 
     * <p><b>HOW IT WORKS:</b>
     * 1. Creates cookies with same name/path/domain as original cookies
     * 2. Sets MaxAge to 0 (expires immediately)
     * 3. Sets empty value (clears the token)
     * 4. Browser removes cookies automatically
     * 
     * <p><b>WHY WE NEED THIS:</b>
     * - When user logs out, we need to remove cookies from browser
     * - Simply deleting server-side isn't enough (cookies still in browser)
     * - Setting MaxAge=0 tells browser to delete the cookie
     * 
     * <p><b>REAL-WORLD SCENARIO:</b>
     * User clicks "Logout" → Backend revokes tokens → Backend calls this method → 
     * Cookies set to expire → Browser deletes cookies → User is logged out
     * 
     * @param response HTTP response object (we add cookie-clearing instructions to this)
     */
    public void clearAuthCookies(HttpServletResponse response) {
        // Determine if we're in production (must match cookie creation settings)
        boolean isProduction = "production".equalsIgnoreCase(environment);
        String sameSiteValue = sameSiteNone && isProduction ? "None" : "Lax";
        
        // Clear access token cookie
        // HOW: Set MaxAge=0 and empty value
        // WHY: Browser automatically deletes cookies with MaxAge=0
        // REAL-WORLD: User logs out → Cookie deleted → Next request has no cookie → User not authenticated
        Cookie accessTokenCookie = new Cookie(ACCESS_TOKEN_COOKIE_NAME, "");
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(isProduction);
        accessTokenCookie.setPath(COOKIE_PATH);
        accessTokenCookie.setMaxAge(0); // Expire immediately (browser deletes it)
        
        if (cookieDomain != null && !cookieDomain.isEmpty()) {
            accessTokenCookie.setDomain(cookieDomain);
        }
        
        accessTokenCookie.setAttribute("SameSite", sameSiteValue);
        
        // Clear refresh token cookie (same process)
        Cookie refreshTokenCookie = new Cookie(REFRESH_TOKEN_COOKIE_NAME, "");
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(isProduction);
        refreshTokenCookie.setPath(COOKIE_PATH);
        refreshTokenCookie.setMaxAge(0); // Expire immediately
        
        if (cookieDomain != null && !cookieDomain.isEmpty()) {
            refreshTokenCookie.setDomain(cookieDomain);
        }
        
        refreshTokenCookie.setAttribute("SameSite", sameSiteValue);
        
        // Add cookie-clearing instructions to response
        // Browser will process these and delete the cookies
        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);
    }
}

