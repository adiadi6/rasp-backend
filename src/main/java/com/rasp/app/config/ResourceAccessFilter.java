//package com.example.demo.config;
//
//import com.example.demo.service.RoleResourceService;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.security.oauth2.jwt.Jwt;
//import org.springframework.security.oauth2.jwt.JwtDecoder;
//import org.springframework.security.oauth2.jwt.JwtException;
//import org.springframework.util.StringUtils;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//import java.util.*;
//
//public class ResourceAccessFilter extends OncePerRequestFilter {
//
//    private final JwtDecoder jwtDecoder;
//    private final RoleResourceService roleResourceService;
//
//    public ResourceAccessFilter(JwtDecoder jwtDecoder, RoleResourceService roleResourceService) {
//        this.jwtDecoder = jwtDecoder;
//        this.roleResourceService = roleResourceService;
//    }
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
//            throws ServletException, IOException {
//
//        String requestURI = request.getRequestURI();
//        if (requestURI.startsWith("/api/auth/login") || requestURI.startsWith("/api/auth/register")) {
//            chain.doFilter(request, response);
//            return;
//        }
//
//        String token = extractToken(request);
//        if (token == null) {
//            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing or invalid token");
//            return;
//        }
//
//        Jwt jwt;
//        try {
//            jwt = jwtDecoder.decode(token);
//        } catch (JwtException e) {
//            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
//            return;
//        }
//
//        List<String> roles = extractRoles(jwt);
//        if (roles.isEmpty()) {
//            response.sendError(HttpServletResponse.SC_FORBIDDEN, "User has no roles assigned");
//            return;
//        }
//
//        String requestedResource = request.getParameter("resource");
//        if (requestedResource == null) {
//            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Resource parameter is missing");
//            return;
//        }
//
//        if (!checkAccess(roles, requestedResource)) {
//            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
//            return;
//        }
//
//        chain.doFilter(request, response);
//    }
//
//    private boolean checkAccess(List<String> roles, String resource) {
//        Map<String, List<String>> roleResourceMap = roleResourceService.getAllRoleResources(); // Fetch from cache
//
//        for (String role : roles) {
//            if (roleResourceMap.containsKey(role) && roleResourceMap.get(role).contains(resource)) {
//                return true; // Grant access if role has the resource
//            }
//        }
//
//        return false; // Deny if no matching role-resource found
//    }
//
//    private String extractToken(HttpServletRequest request) {
//        String header = request.getHeader("Authorization");
//        return (StringUtils.hasText(header) && header.startsWith("Bearer ")) ? header.substring(7).trim() : null;
//    }
//
//    private List<String> extractRoles(Jwt jwt) {
//        List<String> roles = new ArrayList<>();
//
//        try {
//            Map<String, Object> claims = jwt.getClaims();
//
//            if (claims.containsKey("realm_access") && claims.get("realm_access") instanceof Map) {
//                Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
//                if (realmAccess.containsKey("roles") && realmAccess.get("roles") instanceof List) {
//                    roles.addAll((List<String>) realmAccess.get("roles"));
//                }
//            }
//
//            if (claims.containsKey("resource_access") && claims.get("resource_access") instanceof Map) {
//                Map<String, Object> resourceAccess = (Map<String, Object>) claims.get("resource_access");
//                if (resourceAccess.containsKey("spring-backend") && resourceAccess.get("spring-backend") instanceof Map) {
//                    Map<String, Object> clientRoles = (Map<String, Object>) resourceAccess.get("spring-backend");
//                    if (clientRoles.containsKey("roles") && clientRoles.get("roles") instanceof List) {
//                        roles.addAll((List<String>) clientRoles.get("roles"));
//                    }
//                }
//            }
//        } catch (Exception e) {
//            e.printStackTrace(); // Log error
//        }
//
//        return roles;
//    }
//}
