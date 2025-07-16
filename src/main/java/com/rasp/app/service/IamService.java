package com.rasp.app.service;

import com.rasp.app.helper.RoleUserResInstanceHelper;
import com.rasp.app.resource.RoleUserResInstance;
import com.rasp.app.resource.UserResource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;
import platform.helper.BaseHelper;
import platform.resource.BaseResource;
import platform.util.ApplicationException;

import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service

public class IamService {

    String accessToken=null;

    @Value("${clientId}")
    private  String clientId;

    @Value("${clientSecret}")
    private  String clientSecret; // Replace with your actual secret

    @Value("${keycloakTokenUrl}")
    private  String keycloakTokenUrl;

    @Value("${keycloakUrl}")
    private  String keycloakUrl;

    @Value("${authentication-type:auth-code}")
    private String authenticationType;

    @Value("${ResourcePack}")
    private String resourcePackage;

    @Value("${HelperPack}")
    private String helperPackage;

    public ResponseEntity<?> addClientRole(String roleName) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // 🔹 Step 1: Get Admin Access Token using Client Credentials
        MultiValueMap<String, String> tokenRequestBody = new LinkedMultiValueMap<>();
        tokenRequestBody.add("grant_type", "client_credentials");
        tokenRequestBody.add("client_id", clientId);
        tokenRequestBody.add("client_secret", clientSecret);

        HttpEntity<MultiValueMap<String, String>> tokenRequest = new HttpEntity<>(tokenRequestBody, headers);
        ResponseEntity<Map> tokenResponse = restTemplate.exchange(
                keycloakTokenUrl,
                HttpMethod.POST,
                tokenRequest,
                Map.class
        );

        if (!tokenResponse.getStatusCode().is2xxSuccessful()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Failed to get admin token");
        }

        String accessToken = (String) tokenResponse.getBody().get("access_token");

        // 🔹 Step 2: Get the Client ID (UUID) from Keycloak
        HttpHeaders clientHeaders = new HttpHeaders();
        clientHeaders.setBearerAuth(accessToken);
        HttpEntity<Void> clientRequest = new HttpEntity<>(clientHeaders);

        ResponseEntity<List> clientResponse = restTemplate.exchange(
                keycloakUrl+"/clients",
                HttpMethod.GET,
                clientRequest,
                List.class
        );

        if (!clientResponse.getStatusCode().is2xxSuccessful()) {
            return ResponseEntity.status(clientResponse.getStatusCode()).body("Failed to fetch clients");
        }

        List<Map<String, Object>> clients = clientResponse.getBody();
        String clientUUID = clients.stream()
                .filter(client -> clientId.equals(client.get("clientId")))
                .map(client -> (String) client.get("id"))
                .findFirst()
                .orElse(null);

        if (clientUUID == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Client not found");
        }

        // 🔹 Step 3: Create New Role for Client using Client UUID
        HttpHeaders roleHeaders = new HttpHeaders();
        roleHeaders.setContentType(MediaType.APPLICATION_JSON);
        roleHeaders.setBearerAuth(accessToken);

        Map<String, Object> rolePayload = new HashMap<>();
        rolePayload.put("name", roleName);
        rolePayload.put("description", "Auto-created client role");

        HttpEntity<Map<String, Object>> roleRequest = new HttpEntity<>(rolePayload, roleHeaders);
        ResponseEntity<String> roleResponse = restTemplate.exchange(
                keycloakUrl+"/clients/" + clientUUID + "/roles",
                HttpMethod.POST,
                roleRequest,
                String.class
        );

        if (!roleResponse.getStatusCode().is2xxSuccessful()) {
            return ResponseEntity.status(roleResponse.getStatusCode()).body("Failed to create client role");
        }

        return ResponseEntity.ok("Client role '" + roleName + "' added successfully to client '" + clientId + "'");

    }


public ResponseEntity<?> addUser(UserResource userResource) throws NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException, ClassNotFoundException, ApplicationException {
Map<String,Object> resourceMap= userResource.getResourceMap();
Map<String,Object> authMap=userResource.getAuthMap();
String resource=userResource.getResourceName();
    String myClass= resourcePackage+"."+resource;
    Class<BaseResource> clazz = (Class<BaseResource>) Class.forName(myClass);


    BaseResource baseResource= clazz.getDeclaredConstructor().newInstance();
    baseResource.convertMapToResource(resourceMap);

    String myHelper= helperPackage+"."+resource+"Helper";
    Class<BaseHelper> clazz2=(Class<BaseHelper>) Class.forName(myHelper) ;
    BaseHelper baseHelper=clazz2.getDeclaredConstructor().newInstance();
    baseHelper.add(baseResource);


    System.out.println( baseResource.getId()+"1111111111111111222222222222222");

    RestTemplate restTemplate = new RestTemplate();
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

    // Step 1: Get Admin Access Token using Client Credentials Grant
    MultiValueMap<String, String> tokenRequestBody = new LinkedMultiValueMap<>();
    tokenRequestBody.add("grant_type", "client_credentials");
    tokenRequestBody.add("client_id", clientId);
    tokenRequestBody.add("client_secret", clientSecret);

    HttpEntity<MultiValueMap<String, String>> tokenRequest = new HttpEntity<>(tokenRequestBody, headers);
    ResponseEntity<Map> tokenResponse = restTemplate.exchange(
            keycloakTokenUrl,
            HttpMethod.POST,
            tokenRequest,
            Map.class
    );

    if (!tokenResponse.getStatusCode().is2xxSuccessful()) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Failed to get admin token");
    }

    String accessToken = (String) tokenResponse.getBody().get("access_token");

    // Step 2: Create New User in Keycloak
    HttpHeaders userHeaders = new HttpHeaders();
    userHeaders.setContentType(MediaType.APPLICATION_JSON);
    userHeaders.setBearerAuth(accessToken);
    String user= (String) authMap.get("userName");
    String email=  (String) authMap.get("email");
    String firstName= (String) authMap.get("firstName");
    String lastName=(String) authMap.get("lastName");
    String password=(String) authMap.get("password");

    Map<String, Object> userPayload = new HashMap<>();
    userPayload.put("username", user);
    userPayload.put("email",email );
    userPayload.put("enabled", true);
    userPayload.put("emailVerified", true);
    userPayload.put("firstName", firstName);
    userPayload.put("lastName", lastName);

    Map<String, Object> credentials = new HashMap<>();
    credentials.put("type", "password");
    credentials.put("value", password);
    credentials.put("temporary", false);

    // Custom Attributes
    Map<String, List<String>> attributes = new HashMap<>();
    attributes.put("custom_id", List.of( baseResource.getId())); // Correct: List of Strings

    userPayload.put("attributes", attributes); // or any value you want
    userPayload.put("credentials", List.of(credentials));

    HttpEntity<Map<String, Object>> userRequest = new HttpEntity<>(userPayload, userHeaders);

    ResponseEntity<String> userResponse = restTemplate.exchange(
            keycloakUrl+"/users",
            HttpMethod.POST,
            userRequest,
            String.class
    );



    if (!userResponse.getStatusCode().is2xxSuccessful()) {
        return ResponseEntity.status(userResponse.getStatusCode()).body("Failed to create user");
    }
//        } catch (Exception e) {
//            e.printStackTrace();
//        }

//        if(isScoped){
//
//            BaseResource baseResource1=   ResourceRoleHelper.getInstance().getByField(ResourceRole.FIELD_RESOURCE_NAME,resource);
//            ResourceRole resRoleType=(ResourceRole)baseResource1;
//            if(resRoleType==null){
//                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Resource to role access is not there");
//            }
//            if(resRoleType!=null) {
//                addUserResourceRole(resRoleType.getRole(), newUsername, resource, baseResource.getId());
//            }
//        }
    return  ResponseEntity.ok("User created successfully");


}







    public ResponseEntity<?> addUserResourceRole(String roleName, String userName,String resourceType,String resourceId) {
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            // 🔹 Step 1: Get Admin Access Token
            MultiValueMap<String, String> tokenRequestBody = new LinkedMultiValueMap<>();
            tokenRequestBody.add("grant_type", "client_credentials");
            tokenRequestBody.add("client_id", clientId);
            tokenRequestBody.add("client_secret", clientSecret);

            HttpEntity<MultiValueMap<String, String>> tokenRequest = new HttpEntity<>(tokenRequestBody, headers);
            ResponseEntity<Map> tokenResponse = restTemplate.exchange(
                    "http://localhost:8080/realms/new/protocol/openid-connect/token",
                    HttpMethod.POST,
                    tokenRequest,
                    Map.class
            );

            if (!tokenResponse.getStatusCode().is2xxSuccessful()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Failed to get admin token");
            }

            String accessToken = (String) tokenResponse.getBody().get("access_token");

            // 🔹 Step 2: Get User ID
            HttpHeaders authHeaders = new HttpHeaders();
            authHeaders.setBearerAuth(accessToken);
            HttpEntity<Void> userRequest = new HttpEntity<>(authHeaders);

            ResponseEntity<List> userResponse = restTemplate.exchange(
                    "http://localhost:8080/admin/realms/new/users?username=" + userName,
                    HttpMethod.GET,
                    userRequest,
                    List.class
            );



            if (userResponse.getBody().isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
            }

            String userId = ((Map<String, Object>) userResponse.getBody().get(0)).get("id").toString();

            String raspUserId=null;
        List<Map<String, Object>> users = userResponse.getBody();
    Map<String,Object> firstUser= users.get(0);

          Map<String,Object> attributes= (Map<String, Object>) firstUser.get("attributes");
          if(attributes!=null && attributes.containsKey("custom_id")){
         List<String> raspUserIds= (List<String>) attributes.get("custom_id");
              raspUserId=raspUserIds!=null && !raspUserIds.isEmpty() ? raspUserIds.get(0) :null;
          }


            // 🔹 Step 3: Get Client ID
            ResponseEntity<List> clientResponse = restTemplate.exchange(
                    "http://localhost:8080/admin/realms/new/clients?clientId=" + clientId,
                    HttpMethod.GET,
                    userRequest,
                    List.class
            );

            if (clientResponse.getBody().isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Client not found");
            }

            String clientUuid = ((Map<String, Object>) clientResponse.getBody().get(0)).get("id").toString();

            // 🔹 Step 4: Get Client Role
            ResponseEntity<List> roleResponse = restTemplate.exchange(
                    "http://localhost:8080/admin/realms/new/clients/" + clientUuid + "/roles",
                    HttpMethod.GET,
                    userRequest,
                    List.class
            );

            List<Map<String, Object>> roles = roleResponse.getBody();
            Map<String, Object> role = roles.stream()
                    .filter(r -> roleName.equals(r.get("name")))
                    .findFirst()
                    .orElse(null);

            if (role == null) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Role not found");

//                    return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Role not found");

               // return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Role not found");
            }
            // 🔹 Step 5: Assign Role (Content-Type must be JSON)
            HttpHeaders jsonHeaders = new HttpHeaders();
            jsonHeaders.setBearerAuth(accessToken);
            jsonHeaders.setContentType(MediaType.APPLICATION_JSON);

            // 🔹 Step 5: Assign Client Role to User
            HttpEntity<List<Map<String, Object>>> assignRoleRequest = new HttpEntity<>(List.of(role), jsonHeaders);
            ResponseEntity<String> assignRoleResponse = restTemplate.exchange(
                    "http://localhost:8080/admin/realms/new/users/" + userId + "/role-mappings/clients/" + clientUuid,
                    HttpMethod.POST,
                    assignRoleRequest,
                    String.class
            );

            if (!assignRoleResponse.getStatusCode().is2xxSuccessful()) {
                return ResponseEntity.status(assignRoleResponse.getStatusCode()).body("Failed to assign role");
            }

        RoleUserResInstance roleUserResInstance=new RoleUserResInstance();

        roleUserResInstance.setUser_name(userName);
        roleUserResInstance.setKeycloak_user_id(userId);
        roleUserResInstance.setRole_name(roleName);
        roleUserResInstance.setResource_name(resourceType);
        if(resourceId!=null) {
            roleUserResInstance.setResource_id(resourceId);
        }
        roleUserResInstance.setRasp_user_id(raspUserId);
        RoleUserResInstanceHelper.getInstance().add_Nocatch(roleUserResInstance);
        if(resourceId!=null) {
            return ResponseEntity.ok("Role '" + roleName + "' assigned successfully to user '" + userName + "'"+"' and to this instance"+resourceId);
        }
            return ResponseEntity.ok("Role '" + roleName + "' assigned successfully to user '" + userName + "'");
        }

//    public ResponseEntity<?> addUserRoleMapping(String roleName, String userName) {
//        RestTemplate restTemplate = new RestTemplate();
//        HttpHeaders headers = new HttpHeaders();
//        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
//
//        // 🔹 Step 1: Get Admin Access Token
//        MultiValueMap<String, String> tokenRequestBody = new LinkedMultiValueMap<>();
//        tokenRequestBody.add("grant_type", "client_credentials");
//        tokenRequestBody.add("client_id", clientId);
//        tokenRequestBody.add("client_secret", clientSecret);
//
//        HttpEntity<MultiValueMap<String, String>> tokenRequest = new HttpEntity<>(tokenRequestBody, headers);
//        ResponseEntity<Map> tokenResponse = restTemplate.exchange(
//                keycloakTokenUrl,
//                HttpMethod.POST,
//                tokenRequest,
//                Map.class
//        );
//
//        if (!tokenResponse.getStatusCode().is2xxSuccessful()) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Failed to get admin token");
//        }
//
//        String accessToken = (String) tokenResponse.getBody().get("access_token");
//
//        // 🔹 Step 2: Get User ID
//        HttpHeaders authHeaders = new HttpHeaders();
//        authHeaders.setBearerAuth(accessToken);
//        HttpEntity<Void> userRequest = new HttpEntity<>(authHeaders);
//
//        ResponseEntity<List> userResponse = restTemplate.exchange(
//                keycloakUrl+"/users?username=" + userName,
//                HttpMethod.GET,
//                userRequest,
//                List.class
//        );
//
//
//
//        if (userResponse.getBody().isEmpty()) {
//            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
//        }
//
//        String userId = ((Map<String, Object>) userResponse.getBody().get(0)).get("id").toString();
//
//        String raspUserId=null;
//        List<Map<String, Object>> users = userResponse.getBody();
//        Map<String,Object> firstUser= users.get(0);
//
//        Map<String,Object> attributes= (Map<String, Object>) firstUser.get("attributes");
//        if(attributes!=null && attributes.containsKey("custom_id")){
//            List<String> raspUserIds= (List<String>) attributes.get("custom_id");
//            raspUserId=raspUserIds!=null && !raspUserIds.isEmpty() ? raspUserIds.get(0) :null;
//        }
//
//
//        // 🔹 Step 3: Get Client ID
//        ResponseEntity<List> clientResponse = restTemplate.exchange(
//                keycloakUrl+"/clients?clientId=" + clientId,
//                HttpMethod.GET,
//                userRequest,
//                List.class
//        );
//
//        if (clientResponse.getBody().isEmpty()) {
//            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Client not found");
//        }
//
//        String clientUuid = ((Map<String, Object>) clientResponse.getBody().get(0)).get("id").toString();
//
//        // 🔹 Step 4: Get Client Role
//        ResponseEntity<List> roleResponse = restTemplate.exchange(
//                keycloakUrl+"/clients/" + clientUuid + "/roles",
//                HttpMethod.GET,
//                userRequest,
//                List.class
//        );
//
//        List<Map<String, Object>> roles = roleResponse.getBody();
//        Map<String, Object> role = roles.stream()
//                .filter(r -> roleName.equals(r.get("name")))
//                .findFirst()
//                .orElse(null);
//
//        if (role == null) {
//            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Role not found");
//
////                    return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Role not found");
//
//            // return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Role not found");
//        }
//        // 🔹 Step 5: Assign Role (Content-Type must be JSON)
//        HttpHeaders jsonHeaders = new HttpHeaders();
//        jsonHeaders.setBearerAuth(accessToken);
//        jsonHeaders.setContentType(MediaType.APPLICATION_JSON);
//
//        // 🔹 Step 5: Assign Client Role to User
//        HttpEntity<List<Map<String, Object>>> assignRoleRequest = new HttpEntity<>(List.of(role), jsonHeaders);
//        ResponseEntity<String> assignRoleResponse = restTemplate.exchange(
//                keycloakUrl+"/users/" + userId + "/role-mappings/clients/" + clientUuid,
//                HttpMethod.POST,
//                assignRoleRequest,
//                String.class
//        );
//
//        if (!assignRoleResponse.getStatusCode().is2xxSuccessful()) {
//            return ResponseEntity.status(assignRoleResponse.getStatusCode()).body("Failed to assign role");
//        }
//
//        return ResponseEntity.ok("Role '" + roleName + "' assigned successfully to user '" + userName + "'");
//    }
public ResponseEntity<?> addUserRoleMapping(Map<String,Object> map) {
        String roleName= (String) map.get("role");
        String userName=(String) map.get("userName");
    RestTemplate restTemplate = new RestTemplate();
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

    // 🔹 Step 1: Get Admin Access Token
    MultiValueMap<String, String> tokenRequestBody = new LinkedMultiValueMap<>();
    tokenRequestBody.add("grant_type", "client_credentials");
    tokenRequestBody.add("client_id", clientId);
    tokenRequestBody.add("client_secret", clientSecret);

    HttpEntity<MultiValueMap<String, String>> tokenRequest = new HttpEntity<>(tokenRequestBody, headers);
    ResponseEntity<Map> tokenResponse = restTemplate.exchange(
            keycloakTokenUrl,
            HttpMethod.POST,
            tokenRequest,
            Map.class
    );

    if (!tokenResponse.getStatusCode().is2xxSuccessful()) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Failed to get admin token");
    }

    String accessToken = (String) tokenResponse.getBody().get("access_token");

    // 🔹 Step 2: Get User ID
    HttpHeaders authHeaders = new HttpHeaders();
    authHeaders.setBearerAuth(accessToken);
    HttpEntity<Void> userRequest = new HttpEntity<>(authHeaders);

    ResponseEntity<List> userResponse = restTemplate.exchange(
            keycloakUrl+"/users?username=" + userName,
            HttpMethod.GET,
            userRequest,
            List.class
    );



    if (userResponse.getBody().isEmpty()) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
    }

    String userId = ((Map<String, Object>) userResponse.getBody().get(0)).get("id").toString();

    String raspUserId=null;
    List<Map<String, Object>> users = userResponse.getBody();
    Map<String,Object> firstUser= users.get(0);

    Map<String,Object> attributes= (Map<String, Object>) firstUser.get("attributes");
    if(attributes!=null && attributes.containsKey("custom_id")){
        List<String> raspUserIds= (List<String>) attributes.get("custom_id");
        raspUserId=raspUserIds!=null && !raspUserIds.isEmpty() ? raspUserIds.get(0) :null;
    }


    // 🔹 Step 3: Get Client ID
    ResponseEntity<List> clientResponse = restTemplate.exchange(
            keycloakUrl+"/clients?clientId=" + clientId,
            HttpMethod.GET,
            userRequest,
            List.class
    );

    if (clientResponse.getBody().isEmpty()) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Client not found");
    }

    String clientUuid = ((Map<String, Object>) clientResponse.getBody().get(0)).get("id").toString();

    // 🔹 Step 4: Get Client Role
    ResponseEntity<List> roleResponse = restTemplate.exchange(
            keycloakUrl+"/clients/" + clientUuid + "/roles",
            HttpMethod.GET,
            userRequest,
            List.class
    );

    List<Map<String, Object>> roles = roleResponse.getBody();
    Map<String, Object> role = roles.stream()
            .filter(r -> roleName.equals(r.get("name")))
            .findFirst()
            .orElse(null);

    if (role == null) {
        throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Role not found");

//                    return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Role not found");

        // return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Role not found");
    }
    // 🔹 Step 5: Assign Role (Content-Type must be JSON)
    HttpHeaders jsonHeaders = new HttpHeaders();
    jsonHeaders.setBearerAuth(accessToken);
    jsonHeaders.setContentType(MediaType.APPLICATION_JSON);

    // 🔹 Step 5: Assign Client Role to User
    HttpEntity<List<Map<String, Object>>> assignRoleRequest = new HttpEntity<>(List.of(role), jsonHeaders);
    ResponseEntity<String> assignRoleResponse = restTemplate.exchange(
            keycloakUrl+"/users/" + userId + "/role-mappings/clients/" + clientUuid,
            HttpMethod.POST,
            assignRoleRequest,
            String.class
    );

    if (!assignRoleResponse.getStatusCode().is2xxSuccessful()) {
        return ResponseEntity.status(assignRoleResponse.getStatusCode()).body("Failed to assign role");
    }

    return ResponseEntity.ok("Role '" + roleName + "' assigned successfully to user '" + userName + "'");
}
}
