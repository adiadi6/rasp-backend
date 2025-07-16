package com.rasp.app.controller;

import com.rasp.app.resource.UserResource;
import com.rasp.app.service.IamService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import platform.util.ApplicationException;

import java.lang.reflect.InvocationTargetException;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class IamController {
     @Autowired
     IamService iamService;

    @PostMapping("/add-client-role")//add_role
    public ResponseEntity<?> addClientRole(@RequestParam String roleName) {
        return iamService.addClientRole(roleName);
    }


    @PostMapping("/add_user")
    public ResponseEntity<?> registerUser(@RequestBody UserResource userResource) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException, ApplicationException {

        return iamService.addUser(userResource);

    }

//    @PostMapping("/user_resource_role")
//    public ResponseEntity<?> userResourceRole(@RequestParam String role,@RequestParam String userName,@RequestParam String resourceType,@RequestParam String resourceId){
//        return iamService.addUserResourceRole(role,userName,resourceType,resourceId);
//    }
//    @PostMapping("/user_role_mapping")
//    public ResponseEntity<?> userRoleMapping(@RequestParam String role,@RequestParam String userName){
//        return iamService.addUserRoleMapping(role,userName);
//    }
@PostMapping("/user_role_mapping")
public ResponseEntity<?> userRoleMapping(@RequestBody Map<String,Object> map){
    return iamService.addUserRoleMapping(map);
}





}
