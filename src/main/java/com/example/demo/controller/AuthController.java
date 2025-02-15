// Updated AuthController.java
package com.example.demo.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final String clientId = "spring-backend";
    private final String clientSecret = "RWZ07XimADvajYWWCXu84Utu65uCkQaE"; // Replace with your actual secret
    private final String redirectUri = "http://localhost:8082/api/auth/callback";
    private final String keycloakTokenUrl = "http://localhost:8080/realms/demo-realm/protocol/openid-connect/token";

    private final String frontendURL = "http://localhost:5173/cookies";

    @Value("${authentication-type:auth-code}")
    private String authenticationType;


    @GetMapping("/login")
    public void login(@RequestParam(value = "username", required = false) String username,
                      @RequestParam(value = "password", required = false) String password,
                      HttpServletResponse response) throws IOException {
        if ("implicit".equalsIgnoreCase(authenticationType) && username != null && password != null) {
            handleImplicitFlow(username, password, response);
        } else {
            String authUrl = "http://localhost:8080/realms/demo-realm/protocol/openid-connect/auth"
                    + "?client_id=" + clientId
                    + "&response_type=code"
                    + "&scope=openid profile email"
                    + "&redirect_uri=" + redirectUri;
            response.sendRedirect(authUrl);
        }
    }

    private void handleImplicitFlow(String username, String password, HttpServletResponse response) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("grant_type", "password");
        requestBody.add("client_id", clientId);
        requestBody.add("client_secret", clientSecret);
        requestBody.add("username", username);
        requestBody.add("password", password);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(requestBody, headers);
        ResponseEntity<Map> tokenResponse = restTemplate.exchange(keycloakTokenUrl, HttpMethod.POST, request, Map.class);

        if (!tokenResponse.getStatusCode().is2xxSuccessful()) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return;
        }

        Map<String, String> body = tokenResponse.getBody();
        String accessToken = body.get("access_token");
        String refreshToken = body.get("refresh_token");

        setCookie(response, "access_token", accessToken, 900); // 15 minutes expiry
        setCookie(response, "refresh_token", refreshToken, 86400); // 24 hours expiry
    }

    @GetMapping("/callback")
    public ResponseEntity<String> callback(@RequestParam("code") String authCode, HttpServletResponse response) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String requestBody = "grant_type=authorization_code"
                + "&client_id=" + clientId
                + "&client_secret=" + clientSecret
                + "&redirect_uri=" + redirectUri
                + "&code=" + authCode;

        HttpEntity<String> request = new HttpEntity<>(requestBody, headers);
        ResponseEntity<Map> tokenResponse = restTemplate.exchange(keycloakTokenUrl, HttpMethod.POST, request, Map.class);

        if (!tokenResponse.getStatusCode().is2xxSuccessful()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Failed to authenticate");
        }

        Map<String, String> body = tokenResponse.getBody();
        String accessToken = body.get("access_token");
        String refreshToken = body.get("refresh_token");

        setCookie(response, "access_token", accessToken, 900); // 15 minutes expiry
        setCookie(response, "refresh_token", refreshToken, 86400); // 24 hours expiry

        String redirectUrl = frontendURL;

        HttpHeaders redirectHeaders = new HttpHeaders();
        redirectHeaders.setLocation(URI.create(redirectUrl));

//        setCookie(response, "access_token", newAccessToken, 900);
//        setCookie(response, "refresh_token", newRefreshToken, 86400);
//
        return new ResponseEntity<>(redirectHeaders, HttpStatus.FOUND);
//        return ResponseEntity.ok("Login successful");
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@CookieValue(value = "refresh_token", required = false) String refreshToken, HttpServletResponse response) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            System.out.println("No refresh token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token missing");
        }

        // Prepare request parameters as form data (x-www-form-urlencoded)
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("refresh_token", refreshToken);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        RestTemplate restTemplate = new RestTemplate();

        try {
            restTemplate.postForEntity("http://localhost:8080/realms/demo-realm/protocol/openid-connect/logout", request, String.class);
            System.out.println("Logout successful in Keycloak");
        } catch (Exception e) {
            System.err.println("Logout failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Logout failed");
        }

        // Clear cookies
        setCookie(response, "access_token", "", 0);
        setCookie(response, "refresh_token", "", 0);

        return ResponseEntity.ok("Logged out");
    }

    private void setCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(false); // Set to false to allow JavaScript access
        cookie.setSecure(false); // Set to true in HTTPS environments
        cookie.setPath("/"); // Ensure it's accessible everywhere
        cookie.setMaxAge(maxAge);
        cookie.setDomain("localhost"); // Change this for production
        response.addCookie(cookie);
    }
}
