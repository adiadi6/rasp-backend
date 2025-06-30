package com.rasp.app.controller;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class HelloController {

    @GetMapping("/public")
    public String publicEndpoint() {
        return "This is a public endpoint";
    }

    @GetMapping("/user")
//    public String userEndpoint(@AuthenticationPrincipal Jwt jwt) {
//        return "Hello User: " + jwt.getClaimAsString("preferred_username");
//    }

    public ResponseEntity<Map<String, String>> userEndpoint(@AuthenticationPrincipal Jwt jwt) {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Hello User: " + jwt.getClaimAsString("preferred_username"));
        System.out.println("user api hit now");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/admin")
    public String adminEndpoint(@AuthenticationPrincipal Jwt jwt) {
        return "Hello Admin: " + jwt.getClaimAsString("preferred_username");
    }
}
