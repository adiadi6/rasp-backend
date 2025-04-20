## Codebase Explanation

This section explains the implementation details of the integration with Keycloak for authentication and authorization within the application.

### 1. **SecurityConfig.java**
This is the main Spring Security configuration class.

#### Constructor
```java
public SecurityConfig(JwtAuthConverter jwtAuthConverter, JwtDecoder jwtDecoder, JdbcTemplate jdbcTemplate)
```
- Injects three dependencies:
  - `JwtAuthConverter`: converts JWT tokens into Spring Security `Authentication` objects.
  - `JwtDecoder`: decodes and validates JWTs.
  - `JdbcTemplate`: used later in custom filters for DB operations (used in RBAC checks).
---

#### securityFilterChain
```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository) throws Exception
```

This is where the core security rules are defined.

##### `http.cors(...)`
```java
.cors(cors -> cors.configurationSource(corsFilter()))
```
- Enables Cross-Origin Resource Sharing (CORS) using a custom configuration (defined below).

##### `csrf.disable()`
- Disables CSRF protection, which is fine here since you're using token-based stateless authentication (not session-based forms).

##### `session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)`
- Forces Spring Security to **not use sessions**. Every request must be authenticated independently via tokens.

##### `authorizeHttpRequests(...)`
```java
.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/auth/login", "/api/auth/callback", "/api/auth/logout","/api/auth/addUser","/api/auth/register").permitAll()
    .anyRequest().authenticated()
)
```
- Allows unauthenticated access to specified endpoints (login, register, etc.)
- Any other endpoint **requires authentication**.

##### `.addFilterBefore(new KeycloakTokenFilter(), BearerTokenAuthenticationFilter.class)`
- Inserts `KeycloakTokenFilter` **before** the default Spring Security Bearer token filter.
- Used for custom **access token validation and refresh logic**.

##### `.addFilterAfter(new ResourceAccessFilter(...), KeycloakTokenFilter.class)`
- Adds another custom filter (`ResourceAccessFilter`) **after** the `KeycloakTokenFilter` to perform **role-resource based access control (RBAC)**.

##### `.oauth2ResourceServer(oauth2 -> ...)`
```java
.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter)))
```
- Enables OAuth2 Resource Server mode, using JWT tokens.
- Uses `jwtAuthConverter` to convert JWT claims to Spring's authorities.

---

#### corsFilter
```java
@Bean
public CorsConfigurationSource corsFilter()
```
- Explicitly allows requests from the frontend (`http://localhost:5173`)
- Allows specific headers and methods.
- Allows cookies (e.g. refresh token stored in cookies).
- This is necessary for smooth frontend-backend interaction during development.

---

### 2. **KeycloakTokenFilter.java**
This is a **custom authentication filter** that runs before the request hits Spring Security’s core logic.

#### What it does:
- Extracts access token from `Authorization` header.
- Checks if the token is valid using Keycloak’s `token/introspect` endpoint.
- If access token is invalid:
  - Tries to extract a refresh token from cookies.
  - If refresh token is valid, tries to get a new access token from Keycloak’s `token` endpoint.
  - If successful, replaces the request’s access token and retries.
- Authenticates the user manually and sets up Spring Security context.

---

#### `doFilterInternal(...)`
This is the method that’s called once per request.

##### `extractToken(...)`
- Pulls the bearer token from the `Authorization` header.

##### `isTokenValid(...)`
```java
POST /token/introspect
Authorization: Basic base64(client_id:client_secret)
Body: token=<access_token>
```
- Calls Keycloak’s introspect endpoint to verify if token is still active.
- If `"active": true`, token is valid.

##### If access token is **invalid**:
- Check for a cookie called `refresh_token`.
- If present and valid, it calls:
  ```java
  refreshAccessToken(refreshToken)
  ```
- Which sends a `POST` to `/token` to get a new access token:
```java
grant_type=refresh_token
refresh_token=<refresh_token>
client_id=<id>
client_secret=<secret>
```

- If it successfully gets a new token:
  - Sets a new cookie for the frontend.
  - Wraps the original request with updated `Authorization` header.
  - Proceeds with the new request.

##### If all fails, it sends appropriate `403` or `401` errors.

##### Else (if access token is valid):
```java
UserDetails userDetails = new User("user", "", Collections.emptyList());
```
- Manually creates a dummy user (you could improve this).
- Sets up Spring Security authentication context so that other filters and controllers can trust the user is authenticated.

---

### 3. **ResourceAccessFilter.java**
This is a **custom RBAC filter** to check if the user's **roles** allow them to access a specific resource.

#### `doFilterInternal(...)`
- Skips filter for login/register requests.
- Extracts the token and decodes it using `JwtDecoder`.
- Extracts the list of roles from the JWT.
- Extracts the `resource` being accessed via a query param.
- Checks if any role of the user has access to that resource using `roleResourceService`.

---

#### `extractRoles(Jwt jwt)`
This reads roles from JWT’s claims:
```json
"realm_access": {
  "roles": ["admin", "user"]
}
"resource_access": {
  "spring-backend": {
    "roles": ["custom-role"]
  }
}
```
- Adds roles from both `"realm_access"` and `"resource_access"`.

---

#### `checkAccess(...)`
```java
Map<String, List<String>> roleResourceMap = roleResourceService.getAllRoleResources();
```
- Retrieves mapping of roles to resources (likely cached in memory).
- Returns true if any role matches the requested resource.

---

#### Summary of Flow

1. **Request comes in.**
2. **CORS** rules are applied.
3. **KeycloakTokenFilter** checks access token:
   - If invalid, tries refresh token.
   - If both fail → reject.
   - Else → updates `Authorization` header and continues.
4. **ResourceAccessFilter** (RBAC):
   - Validates role-resource access for authenticated users.
   - If authorized → continues.
5. **Spring Security** sees valid JWT (converted by `JwtAuthConverter`) and allows access to controller logic.

Sure! Here's a `README` description for the `AuthController.java`:

---

### AuthController Overview

This `AuthController` class is part of the Spring Boot backend, which facilitates authentication and user management with Keycloak. The class is designed to handle various authentication workflows, including both **Implicit Flow** and **Authorization Code Flow** for logging in users, as well as user creation, role assignment, and client role management. The `AuthController` uses Keycloak as the identity provider for user management and authentication.

#### Key Features

1. **Login Endpoint (`/login`)**  
   This endpoint initiates the login process. It determines the authentication flow based on the configuration (`authentication-type`).  
   - **Implicit Flow**: If the configuration is set to `"implicit"`, it will authenticate the user directly using the username and password.
   - **Authorization Code Flow**: If the configuration is set to any other value (default to `"auth-code"`), it will redirect the user to the Keycloak authentication page to retrieve an authorization code.

2. **Callback Endpoint (`/callback`)**  
   After the user has authenticated via Keycloak, this endpoint receives the authorization code from the Keycloak server. The server then exchanges this code for tokens (access and refresh tokens), which are returned to the client as cookies.  
   The cookies (`access_token`, `refresh_token`) are used for user authentication in subsequent API requests.

3. **Add User Endpoint (`/addUser`)**  
   This endpoint allows an admin to create a new user in Keycloak. The admin needs to provide credentials (username, password) to obtain an access token, which is used to make a `POST` request to the Keycloak Admin API to create a new user.

4. **Register User Endpoint (`/register`)**  
   This endpoint allows for registering a new user in Keycloak by a client application. The new user’s credentials are provided, and the backend uses client credentials (client ID and secret) to authenticate and authorize the request, then create the user in Keycloak.

5. **Add Client Role Endpoint (`/add-client-role`)**  
   This endpoint allows the creation of a new role for a Keycloak client. It first retrieves the access token, fetches the client ID, and then creates a new role for the client in Keycloak using the `POST` method.

6. **Assign Client Role Endpoint (`/assign-client-role`)**  
   This endpoint assigns a role to a user in Keycloak. It takes the username and role name as parameters, retrieves the admin token, and then assigns the role to the specified user.

#### Keycloak Integration

- **Keycloak Token URL**: The Keycloak URL is hardcoded as `http://localhost:8080/realms/demo-realm/protocol/openid-connect/token` for acquiring tokens. You may need to replace this with your actual Keycloak server URL.
- **Token Management**: The tokens received are stored in cookies (`access_token`, `refresh_token`) with appropriate expiry times. The cookies help in maintaining the user’s session in subsequent requests.

