package com.example.demo.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtCookieFilter extends OncePerRequestFilter {

    private final JwtDecoder jwtDecoder;

    public JwtCookieFilter(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String token = extractTokenFromCookies(request);

        System.out.println("working or not");

        if (token != null) {
            try {
                Jwt jwt = jwtDecoder.decode(token);
                System.out.println("Decoded JWT: " + jwt.getClaims());
                JwtAuthenticationToken authToken = new JwtAuthenticationToken(jwt);
                SecurityContext context = new SecurityContextImpl(authToken);
                SecurityContextHolder.setContext(context);
                SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
            } catch (Exception e) {
                System.out.println("Invalid JWT token in cookie: " + e.getMessage());
            }
        }

//        System.out.println("Security Context Authentication: " + SecurityContextHolder.getContext().getAuthentication());

        filterChain.doFilter(request, response);
    }

    private String extractTokenFromCookies(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("access_token".equals(cookie.getName())) {
                    System.out.println("Extracted Token: " + cookie.getValue());
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
