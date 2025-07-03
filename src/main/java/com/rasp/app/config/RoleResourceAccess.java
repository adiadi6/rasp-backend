package com.rasp.app.config;

import com.rasp.app.controller.MetaDataController;
import com.rasp.app.helper.RoleResourcePermissionHelper;
import com.rasp.app.helper.RoleUserResInstanceHelper;
import com.rasp.app.resource.MetaDataDto;
import com.rasp.app.resource.RoleResourcePermission;
import com.rasp.app.resource.RoleUserResInstance;
import jakarta.servlet.http.HttpServletRequest;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import platform.db.Expression;
import platform.db.REL_OP;
import platform.resource.BaseResource;

import org.springframework.context.annotation.Scope;

import java.io.UnsupportedEncodingException;
import java.util.*;

@Component
@Scope("singleton")
public class RoleResourceAccess {

    //  private final ApplicationContext applicationContext; // Access ApplicationContext
    private static RoleResourceAccess instance;

    private static final String clientId="adi-rest-api";

//    @Autowired
//    private CacheManager cacheManager;
//
//    public void setCacheManager(CacheManager cacheManager) {
//        if (cacheManager == null) {
//            System.out.println("cachemanager is null");
//            return;
//        }
//        this.cacheManager = cacheManager;
//        System.out.println("cachemanager is set to : " + cacheManager);
//    }
//      public RoleResourceAccess(ApplicationContext applicationContext) {
//        this.applicationContext = applicationContext;
//    }


    /*
     * This method returns true if the user has access to the API being called.
     * This method looks at userId, role, resource type and resource Id (optional) and API being accessed.
     * The logic to allow/deny a request is present in this method.
     * return: true/false
     * */
    String resourceName = null;
    String userId;

    HttpServletRequest req = null;
    List<String> roles;

    String role;



    public boolean getAccess(HttpServletRequest request) throws UnsupportedEncodingException {
        req = request;
        String requestURI = request.getRequestURI();

// Remove query parameters if present by taking everything before the "?"
        String path = requestURI.split("\\?")[0];

// Split the URI path by "/" and get the last segment
        String[] pathSegments = path.split("/");

// The last segment will be the last element in the array
        resourceName = pathSegments[pathSegments.length - 1];

        String action = null;
        String resourceId = null;

        String queryId = request.getParameter("queryId");
        if (queryId != null)
            action = request.getParameter("queryId");

        String method = request.getMethod();
        if ("POST".equalsIgnoreCase(method)) {
            if (request.getParameter("action") == null) {
                action = "add";
            } else {
                action = request.getParameter("action");
            }

        }
        if (!"add".equals(action) && !"GET_ALL".equals(queryId) && !"DELETE_ALL".equals(queryId)) {//config file
            String resourceEncoded = request.getParameter("resource");

            if (resourceEncoded == null) {
                String argsParam = request.getParameter("args");
                if (argsParam != null && argsParam.contains(":")) {
                    String[] parts = argsParam.split(":", 2); // Split into key and value
                    String key = parts[0].trim();   // "ID"
                    String value = parts[1].trim();

                    if ("ID".equals(key)) {
                        resourceId = value;
                    }
                }
            }
            if (resourceEncoded != null) {

                byte[] decodedByte = Base64.getDecoder().decode(resourceEncoded);
                String json = new String(decodedByte, "UTF-8");

                JSONObject object = new JSONObject(json);
                if (object.getString("id") != null) {
                    resourceId = object.getString("id");
                } else {
                    String argsParam = request.getParameter("args");
                    if (argsParam != null && argsParam.contains(":")) {
                        String[] parts = argsParam.split(":", 2); // Split into key and value
                        String key = parts[0].trim();   // "ID"
                        String value = parts[1].trim();

                        if ("ID".equals(key)) {
                            resourceId = value;
                        }
                    }
                }
            }
        }


        roles = getRoles();
        userId = getUserId();
        BaseResource baseResource = null;
//        for(String role:roles) {
//
//
//            roleResource = (RoleResource) RoleResourceHelper.getInstance().
//                    getByExpressionFirstRecord(Expression.and(new Expression(RoleResource.
//                                    FIELD_ROLE_NAME, REL_OP.EQ, role),
//                            new Expression(RoleResource.FIELD_ACTION, REL_OP.EQ, action),
//                            new Expression(RoleResource.FIELD_RESOURCE, REL_OP.EQ, resourceName)));
//
//            if(roleResource!=null) break;
//        }
//        return roleResource;
//        RoleResource roleResources=null;
//        for(String role:roles) {
//           roleResources=  getUsersFromCache(resourceName, action, role);
//          if(roleResources!=null)
//              break;
//        }
//        return roleResources;

        for (String role : roles) {


            //baseResource = accessLogic(role, action, resourceName, resourceId, userId);
            baseResource = accessLogic(role, action, resourceName );


            if (baseResource != null)
                return true;
        }
         return false;

    }

    public static String getUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String raspuserId = null;
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            raspuserId = jwt.getClaim("custom_id");
        }
        return raspuserId;
    }

    public static List<String> getRoles() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Map<String, String> response = new HashMap<>();
        List<String> roles = new ArrayList<>();
        // Check if the authentication object is not null and contains a Jwt principal
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();


            response.put("message", "Hello User: " + jwt.getClaimAsString("preferred_username"));

            Object realmAccess = jwt.getClaim("realm_access");
            System.out.println("Realm Access: " + realmAccess);

            // Get roles from resource_access for the specific client (e.g., adi-rest-api)
            Object resourceAccess = jwt.getClaim("resource_access");
            System.out.println("Resource Access: " + resourceAccess);

            if (realmAccess != null) {
                Map<String, Object> realmAccessMap = (Map<String, Object>) realmAccess;
                List<String> realmRoles = (List<String>) realmAccessMap.get("roles");
                roles = realmRoles;
                response.put("realmRoles", String.valueOf(realmRoles));
            }

            if (resourceAccess != null) {
                Map<String, Object> resourceAccessMap = (Map<String, Object>) resourceAccess;
                Map<String, Object> clientRoles = (Map<String, Object>) resourceAccessMap.get(clientId);
                if (clientRoles != null) {
                    List<String> clientRolesList = (List<String>) clientRoles.get("roles");
                    roles.addAll(clientRolesList);

                    System.out.println(roles);
                    response.put("clientRoles", String.valueOf(clientRolesList));
                }
            }

            // Get roles from realm_access
        }
        System.out.println("user api hit now");
        return roles;

    }

    // Method to get users from cache based on dynamic keys
//    public RoleResource getUsersFromCache(String resourceName, String action, String role) {
//        // Constructing a dynamic cache key based on the parameters
//        String cacheKey = generateCacheKey(resourceName, action, role);
//
//        // Access the cache manager and get the cache by name
//        Cache cache = cacheManager.getCache("roleResourceCache");
//        if (cache != null) {
//            BaseResource[] cachedResources = cache.get("allUsersKey", BaseResource[].class);
//            // Retrieve the cached result using the dynamically generated key
////            List<RoleResource> cachedUsers = cache.get(cacheKey, List.class);
////            if (cachedUsers != null) {
////                System.out.println("Fetching data from cache...");
////                return cachedUsers; // Return cached data if found
////            }
//
//            if (cachedResources != null) {
//                // Iterate through the array to find the specific object based on resourceName, action, and role
//                for (BaseResource resource : cachedResources) {
//                    RoleResource roleResource = (RoleResource) resource;
//                    List<String> actions = roleResource.getAction();
//                    for (String a : actions) {
//                        if (roleResource.getResource().equals(resourceName) &&
//                                action.equals(a) &&
//                                roleResource.getRole_name().equals(role)
//                        ) {
//                            return roleResource;
//                        }
//                    }
//                    System.out.println("Found resource with resourceName: " + resourceName + ", action: " + action + ", role: " + role);
//                }
//            }
//            return null;
//        }
//        return null;
//    }

    // Helper method to generate cache key dynamically
    private String generateCacheKey(String resourceName, String action, String role) {
        return resourceName + ":" + action + ":" + role; // Unique cache key based on parameters
    }

    public static RoleResourceAccess getInstance() {
        if (instance == null) {
            instance = new RoleResourceAccess();  // Create the instance if it doesn't exist
        }
        return instance;
    }

    public static RoleResourceAccess getInstance(CacheManager cacheManager) {
        if (instance == null) {
            instance = new RoleResourceAccess();
           // instance.setCacheManager(cacheManager);// Create the instance if it doesn't exist
        }
        return instance;
    }

    /*
     * This method contains the logic to allow/deny a request.
     * This looks at role, action, resource type, resource ID & userId
     * */
//    private BaseResource accessLogic(String role, String action, String resourceName, String resourceInstance, String userId) throws UnsupportedEncodingException {
//        if (action.equals("add") || action.equals("GET_ALL") || action.equals("DELETE_aLL")) {
//            RoleResourcePermission roleResourcePermission = (RoleResourcePermission) RoleResourcePermissionHelper.getInstance().
//                    getByExpressionFirstRecord(Expression.and(new Expression(RoleResourcePermission.
//                                    FIELD_ROLE, REL_OP.EQ, role),
//                            new Expression(RoleResourcePermission.FIELD_ACTION, REL_OP.EQ, action),
//                            new Expression(RoleResourcePermission.FIELD_RESOURCE, REL_OP.EQ, resourceName)));
//
//            if (roleResourcePermission != null) {
//                this.role=role;
//                if(action.equals("add")){
//                Boolean hasAccess= getForeignAccess();
//                if(hasAccess==false){
//                    return null;
//                }
//                else {
//
//                    return roleResourcePermission;
//
//                }
//             }
//
//            }
//        }
////      BaseResource[] baseResources= RoleUserResInstanceHelper.getInstance().
////                                   getByExpression(Expression.and(new Expression(RoleUserResInstance.
////                                   FIELD_RASP_USER_ID, REL_OP.EQ, userId), new Expression(RoleResourcePermission.FIELD_ROLE_NAME, REL_OP.EQ, role)
////                                           , new Expression(RoleResourcePermission.FIELD_RESOURCE, REL_OP.EQ,resourceName )));
////
////        RoleUserResInstance[] roleUserResInstances= (RoleUserResInstance[]) baseResources;
////for(RoleUserResInstance roleUserResInstance:roleUserResInstances){
//
//        if (resourceInstance == null) {
//
//            RoleResourcePermission roleResourcePermission = (RoleResourcePermission) RoleResourcePermissionHelper.getInstance().
//                    getByExpressionFirstRecord(Expression.and(new Expression(RoleResourcePermission.
//                                    FIELD_ROLE, REL_OP.EQ, role),
//                            new Expression(RoleResourcePermission.FIELD_ACTION, REL_OP.EQ, action),
//                            new Expression(RoleResourcePermission.FIELD_RESOURCE, REL_OP.EQ, resourceName)));
//
//            if (roleResourcePermission != null) {
//                return roleResourcePermission;
//            }
//        }
//        RoleResourcePermission roleResourcePermission = (RoleResourcePermission) RoleResourcePermissionHelper.getInstance().
//                getByExpressionFirstRecord(Expression.and(new Expression(RoleResourcePermission.
//                                FIELD_ROLE, REL_OP.EQ, role),
//                        new Expression(RoleResourcePermission.FIELD_ACTION, REL_OP.EQ, action),
//                        new Expression(RoleResourcePermission.FIELD_RESOURCE, REL_OP.EQ, resourceName)));
//
//        if (roleResourcePermission != null) {
//            RoleUserResInstance roleUserResInstance1 = (RoleUserResInstance) RoleUserResInstanceHelper.getInstance().
//                    getByExpressionFirstRecord(Expression.and(new Expression(RoleUserResInstance.
//                                    FIELD_ROLE_NAME, REL_OP.EQ, role),
//                            new Expression(RoleUserResInstance.FIELD_RASP_USER_ID, REL_OP.EQ, userId),
//                            new Expression(RoleUserResInstance.FIELD_RESOURCE_ID, REL_OP.EQ, resourceInstance)));
//            if (roleUserResInstance1 != null) {
//                return roleUserResInstance1;
//
//            }
//
//        }
//
//
//        return null;
//    }

    private BaseResource accessLogic(String role, String action, String resourceName) throws UnsupportedEncodingException {

            RoleResourcePermission roleResourcePermission = (RoleResourcePermission) RoleResourcePermissionHelper.getInstance().
                    getByExpressionFirstRecord(Expression.and(new Expression(RoleResourcePermission.
                                    FIELD_ROLE, REL_OP.EQ, role),
                            new Expression(RoleResourcePermission.FIELD_ACTION, REL_OP.EQ, action),
                            new Expression(RoleResourcePermission.FIELD_RESOURCE, REL_OP.EQ, resourceName)));
            if (roleResourcePermission != null) {
                        return roleResourcePermission;
            }
        return null;
    }

    public boolean getForeignAccess() throws UnsupportedEncodingException {

        String user = getUserId();
        String res = resourceName;
        List<Map<String, String>> foreignResource = new ArrayList<>();
        List<MetaDataDto> dtos =new MetaDataController().processMetadata(resourceName);
        List<Map<String, Object>> fields = dtos.getFirst().getFieldValues();
        for (Map<String, Object> field : fields) {
            if (field.containsKey("foreign")) {
                String fKey = (String) field.get("foreign");
                String fName = (String) field.get("name");
                Map<String, String> foreignMap = new HashMap<>();
                foreignMap.put("resource", fKey);
                foreignMap.put("name", fName);
                foreignResource.add(foreignMap);
            }
        }
        if (!foreignResource.isEmpty()) {
            String base64Encoded = req.getParameter("resource");
            byte[] decodedBytes = Base64.getDecoder().decode(base64Encoded);
            String json = new String(decodedBytes, "UTF-8");

            // Parse JSON
            JSONObject object = new JSONObject(json);

            for (Map<String, String> foreignField : foreignResource) {
                String resource = foreignField.get("resource");
                String updatedResource = resource.substring(0, 1).toLowerCase() + resource.substring(1);
                String fieldName = foreignField.get("name");
                String foreign_id = object.getString(fieldName);


                RoleResourcePermission roleResourcePermission = (RoleResourcePermission) RoleResourcePermissionHelper.getInstance().
                        getByExpressionFirstRecord(Expression.and(new Expression(RoleResourcePermission.
                                        FIELD_ROLE, REL_OP.EQ, role),
                                new Expression(RoleResourcePermission.FIELD_ACTION, REL_OP.EQ, clientId),
                                new Expression(RoleResourcePermission.FIELD_RESOURCE, REL_OP.EQ, updatedResource)));

                if(roleResourcePermission==null){
                    return false;
                }
                else{

                    RoleUserResInstance roleUserResInstance1 = (RoleUserResInstance) RoleUserResInstanceHelper.getInstance().
                            getByExpressionFirstRecord(Expression.and(new Expression(RoleResourcePermission.
                                            FIELD_ROLE, REL_OP.EQ, role),
                                    new Expression(RoleUserResInstance.FIELD_RASP_USER_ID, REL_OP.EQ, userId),
                                    new Expression(RoleUserResInstance.FIELD_RESOURCE_ID, REL_OP.EQ, foreign_id)));

                    if (roleUserResInstance1 == null) {
                        return false;
                    }
                }
            }


        }
        else{
            return true;
        }

    return true;
    }
}
