package com.example.demo.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class KeycloakTokenFilter extends OncePerRequestFilter {

    private static final String INTROSPECT_URL = "http://localhost:8080/realms/demo-realm/protocol/openid-connect/token/introspect";
    private static final String REFRESH_URL = "http://localhost:8080/realms/demo-realm/protocol/openid-connect/token";

    private static final String CLIENT_ID = "spring-backend";
    private static final String CLIENT_SECRET = "RWZ07XimADvajYWWCXu84Utu65uCkQaE";

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String accessToken = extractToken(request);
        if (accessToken == null) {
            chain.doFilter(request, response);
            return;
        }

        // Validate token
        if (!isTokenValid(accessToken)) {
            System.out.println("done with validating access token");
            String refreshToken = extractRefreshToken(request);
            if(!isTokenValid(refreshToken)) {
                System.out.println("refresh token also not valid now");
                response.sendError(HttpServletResponse.SC_FORBIDDEN,"Refresh token not valid, login karlo");
                return;
            }
            if (refreshToken != null) {
                accessToken = refreshAccessToken(refreshToken);
                if (accessToken != null) {
//                    response.setHeader("Authorization", "Bearer " + accessToken);
//                    System.out.println(accessToken);
                    // Set new access token in request header
//                    request.setAttribute("Authorization", "Bearer " + accessToken);
                    // Re-attempt the same request with the new access token
//                    doFilterInternal(request, response, chain);

                    final String newAccessToken = accessToken;

                    // Wrap the request with the new Authorization header
                    HttpServletRequest modifiedRequest = new HttpServletRequestWrapper(request) {
                        @Override
                        public String getHeader(String name) {
                            if ("Authorization".equalsIgnoreCase(name)) {
                                return "Bearer " + newAccessToken; // Set new token
                            }
                            return super.getHeader(name);
                        }
                    };

                    // Proceed with the modified request
                    chain.doFilter(modifiedRequest, response);
                    return;
                } else {
                    System.out.print("access token retrieval issue");
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Token");
                    return;
                }
            } else {
                System.out.println("refresh token retrieval issue");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                return;
            }
        }

        // Authenticate user in Spring Security
        UserDetails userDetails = new User("user", "", Collections.emptyList());
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);
    }

    public boolean isTokenValid(String token) {
        try {
            RestTemplate restTemplate = new RestTemplate();
            ObjectMapper objectMapper = new ObjectMapper();

            // Prepare the request headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.setBasicAuth(CLIENT_ID, CLIENT_SECRET); // Adds Authorization: Basic <base64(client_id:client_secret)>

            // Prepare the request body
            String body = "token=" + token;

            HttpEntity<String> requestEntity = new HttpEntity<>(body, headers);

            // Send the request
            ResponseEntity<String> response = restTemplate.exchange(INTROSPECT_URL, HttpMethod.POST, requestEntity, String.class);

            // Parse response
            JsonNode json = objectMapper.readTree(response.getBody());
            System.out.println(json);

            return json.get("active").asBoolean();
        } catch (Exception e) {
            System.out.println("wrong");
            System.out.println(e.getMessage());
            return false;
        }
    }

    private String refreshAccessToken(String refreshToken) {
        try {
            RestTemplate restTemplate = new RestTemplate();
            ObjectMapper objectMapper = new ObjectMapper();

            // Set headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            // Request body as URL-encoded string
            String body = "grant_type=refresh_token" +
                    "&refresh_token=" + refreshToken +
                    "&client_id=" + CLIENT_ID +
                    "&client_secret=" + CLIENT_SECRET;

            HttpEntity<String> requestEntity = new HttpEntity<>(body, headers);

            // Send the request
            ResponseEntity<String> response = restTemplate.exchange(
                    REFRESH_URL, HttpMethod.POST, requestEntity, String.class
            );

            // Parse response
            JsonNode json = objectMapper.readTree(response.getBody());
            System.out.println(json);
//            System.out.println(json.has("access_token") ? json.get("access_token").asText() : null);

            // Extract and return the new access token
            return json.has("access_token") ? json.get("access_token").asText() : null;
        } catch (Exception e) {
            System.out.println("Error refreshing token: " + e.getMessage());
            return null;
        }
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        return (StringUtils.hasText(header) && header.startsWith("Bearer ")) ? header.substring(7) : null;
    }

    private String extractRefreshToken(HttpServletRequest request) {
        if (request.getCookies() != null) {
            System.out.println("Cookies found!!");
            for (Cookie cookie : request.getCookies()) {
                if ("refresh_token".equals(cookie.getName())) {
//                    System.out.println(cookie.getValue());
                    return cookie.getValue();
                }
            }
        }
        System.out.println("No Cookies found");
        return null;
    }
}
