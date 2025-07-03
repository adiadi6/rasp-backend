package com.rasp.app.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;


public class RoleFilter extends OncePerRequestFilter {
    // Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {


        List<String> roles=RoleResourceAccess.getRoles();
        if (request.getRequestURI().equals("/api/auth/login") ||
                request.getRequestURI().equals("/api/v1/role_resource")||
                request.getRequestURI().startsWith("/api/auth/callback") ||
                request.getRequestURI().startsWith("/api/sign/batch")||
                request.getRequestURI().startsWith("admin/realms/new/users")||
                request.getRequestURI().startsWith("/api/auth/register")||
               request.getRequestURI().startsWith("/api/auth/addUser")||
                request.getRequestURI().equals( "/api/auth/add-client-role")||
                request.getRequestURI().equals("/api/auth/assign-client-role")||
                request.getRequestURI().equals("/api/auth/user_resource_role")||
                request.getRequestURI().equals("/api/role_resource_permission")||
                request.getRequestURI().equals("/api/auth/add_user")||
                request.getRequestURI().equals("/api/generateApp")||
                request.getRequestURI().equals("/api/resource_role")||
                request.getRequestURI().equals("/api/auth/user_role_mapping")||
                request.getRequestURI().equals("/api/getAllResourceMetaData")||
                request.getRequestURI().equals("/api/GetAllResource")||
                request.getRequestURI().startsWith("/api/getAllResourceMetaData/")||
                request.getRequestURI().startsWith("/api/auth/logout")) {
            filterChain.doFilter(request, response); // Allow the request to continue without role checks
            return;
        }


        RoleResourceAccess roleResourceAccess= RoleResourceAccess.getInstance();
        boolean baseResource=    roleResourceAccess.getAccess(request);//true or false


        if (!baseResource) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
            return;

        }

        filterChain.doFilter(request, response);
    }

}
