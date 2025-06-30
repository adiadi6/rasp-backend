//package com.example.demo.controller;
//
//import com.example.demo.service.RoleResourceService;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.List;
//
//@RestController
//@RequestMapping("/api/roles")  // Ensure this base path matches your request
//public class RoleResourceController {
//
//    private final RoleResourceService roleResourceService;
//
//    public RoleResourceController(RoleResourceService roleResourceService) {
//        this.roleResourceService = roleResourceService;
//    }
//
////    @GetMapping("/{role}")
////    public List<String> getResourcesByRole(@PathVariable String role) {
////        return roleResourceService.getResourcesByRole(role);
////    }
//
////    @DeleteMapping("/cache/{role}")
////    public String clearRoleCache(@PathVariable String role) {
////        roleResourceService.evictRoleCache(role);
////        return "Cache cleared for role: " + role;
////    }
//
//    @DeleteMapping("/cache")
//    public String clearAllCache() {
//        roleResourceService.evictAllRolesCache();
//        return "All role cache cleared";
//    }
//}
