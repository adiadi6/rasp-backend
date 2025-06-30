//package com.example.demo.service;
//
//import org.springframework.cache.annotation.CacheEvict;
//import org.springframework.cache.annotation.Cacheable;
//import org.springframework.jdbc.core.JdbcTemplate;
//import org.springframework.stereotype.Service;
//
//import java.util.*;
//
//@Service
//public class RoleResourceService {
//
//    private final JdbcTemplate jdbcTemplate;
//
//    public RoleResourceService(JdbcTemplate jdbcTemplate) {
//        this.jdbcTemplate = jdbcTemplate;
//    }
//
//    // Load role-resource mapping from DB and store in cache
//    @Cacheable(value = "roleResourceCache", key = "'allRoles'")
//    public Map<String, List<String>> getAllRoleResources() {
//        System.out.println("Reading from SQL");
//        String query = "SELECT role, resource FROM role_resource";
//        List<Map<String, Object>> rows = jdbcTemplate.queryForList(query);
//
//        Map<String, List<String>> roleResourceMap = new HashMap<>();
//        for (Map<String, Object> row : rows) {
//            String role = (String) row.get("role");
//            String resource = (String) row.get("resource");
//            roleResourceMap.computeIfAbsent(role, k -> new ArrayList<>()).add(resource);
//        }
//
//        return roleResourceMap;
//    }
//
//    // Retrieve resources for a specific role from cache
////    public List<String> getResourcesByRole(String role) {
////        return getAllRoleResources().getOrDefault(role, Collections.emptyList());
////    }
//
//    // Clear cache for a specific role
////    @CacheEvict(value = "roleResourceCache", allEntries = true)
////    public void evictRoleCache(String role) {
////        System.out.println("Cache cleared for role: " + role);
////    }
//
//    // Clear all cache
//    @CacheEvict(value = "roleResourceCache", allEntries = true)
//    public void evictAllRolesCache() {
//        System.out.println("All role cache cleared");
//    }
//}
