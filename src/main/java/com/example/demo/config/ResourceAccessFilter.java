package com.example.demo.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.keycloak.representations.AccessToken;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;

public class ResourceAccessFilter extends OncePerRequestFilter {

    private final JwtDecoder jwtDecoder;
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper(); // JSON parser

    public ResourceAccessFilter(JwtDecoder jwtDecoder, JdbcTemplate jdbcTemplate) {
        this.jwtDecoder = jwtDecoder;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        System.out.println("HI");
        // Skip the filter for authentication endpoints
        String requestURI = request.getRequestURI();
        if (requestURI.startsWith("/api/auth/login") || requestURI.startsWith("/api/auth/register")) {
            chain.doFilter(request, response);
            return;
        }

        String token = extractToken(request);
        if (token == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing or invalid token");
            return;
        }

        System.out.println("BRUH..step 2");

        // Decode JWT token
        Jwt jwt = jwtDecoder.decode(token);
        List<String> roles = extractRoles(jwt); // Extract roles properly

        if (roles.isEmpty()) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "User has no roles assigned");
            return;
        }

        System.out.println("hiii..step 3");

        // Extract requested resource from the request parameter
        String requestedResource = request.getParameter("resource");
        if (requestedResource == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Resource parameter is missing");
            return;
        }

        // Check database for role-resource mapping
        boolean hasAccess = checkAccess(roles, requestedResource);

        if (!hasAccess) {
            System.out.println("Access Denied");
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
            return;
        }

        // Proceed with the request if access is granted
        chain.doFilter(request, response);
    }

    private boolean checkAccess(List<String> roles, String resource) {
        String query = "SELECT COUNT(*) FROM role_resource WHERE role IN (?) AND resource = ?";

        for (String role : roles) {
            Integer count = jdbcTemplate.queryForObject(query, Integer.class, role, resource);
            if (Objects.requireNonNull(count) > 0) {
                return true; // Access granted if at least one role has access to the resource
            }
        }
        return false;
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        return (StringUtils.hasText(header) && header.startsWith("Bearer ")) ? header.substring(7) : null;
    }


    private List<String> extractRoles(Jwt jwt) {
        List<String> roles = new ArrayList<>();

        try {
            objectMapper.registerModule(new JavaTimeModule());
            JsonNode jwtClaims = objectMapper.readTree(objectMapper.writeValueAsString(jwt.getClaims()));

            // Extract realm-level roles
            JsonNode realmRolesNode = jwtClaims.path("realm_access").path("roles");
            if (realmRolesNode.isArray()) {
                realmRolesNode.forEach(role -> roles.add(role.asText()));
            }

            // Extract client-specific roles (spring-backend)
            JsonNode clientRolesNode = jwtClaims.path("resource_access").path("spring-backend").path("roles");
            if (clientRolesNode.isArray()) {
                clientRolesNode.forEach(role -> roles.add(role.asText()));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return roles;
    }
}