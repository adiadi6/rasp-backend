// Updated AuthController.java
package com.example.demo.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
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

    @GetMapping("/login")
    public void login(HttpServletResponse response) throws IOException {
        String authUrl = "http://localhost:8080/realms/demo-realm/protocol/openid-connect/auth"
                + "?client_id=" + clientId
                + "&response_type=code"
                + "&scope=openid profile email"
                + "&redirect_uri=" + redirectUri;
        response.sendRedirect(authUrl);
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

//    @PostMapping("/logout")
////    @CrossOrigin(origins = "http://localhost:5173", allowCredentials = "true")
//    public ResponseEntity<String> logout(@CookieValue(value = "refresh_token", required = false) String refreshToken, HttpServletResponse response) {
//        if (refreshToken == null || refreshToken.isEmpty()) {
//            System.out.println("No refresh token");
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token missing");
//        }
//        if (refreshToken != null) {
//            RestTemplate restTemplate = new RestTemplate();
//            Map<String, String> body = new HashMap<>();
//            body.put("client_id", clientId);
//            body.put("client_secret", clientSecret);
//            body.put("refresh_token", refreshToken);
//            restTemplate.postForEntity("http://localhost:8080/realms/demo-realm/protocol/openid-connect/logout", body, String.class);
//        }
//
////        setCookie(response, "access_token", "", 0);
////        setCookie(response, "refresh_token", "", 0);
//        return ResponseEntity.ok("Logged out");
//    }

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
