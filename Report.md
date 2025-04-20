# Keycloak Integration with Springboot Application


## Project Overview

This project demonstrates the integration of **Keycloak** with a **Spring Boot** application to manage authentication and authorization. The purpose of this integration is to showcase how Keycloak can be used as an Identity and Access Management (IAM) system to secure a web application.

The README is structured as follows:
1. **Running the Application**: Detailed instructions on setting up and running the application along with Keycloak integration.
2. **Request Flow Explanation**: An overview of what happens when a request hits the backend, including how authentication and authorization are managed by Keycloak and Spring Security.
3. **Codebase Breakdown**: A deep dive into the project’s structure and explanation of the codebase.


---
## Setup and Running the Application

This section will guide you through setting up the project and running it locally. 
<!-- The application demonstrates integration between **Keycloak** and a **Spring Boot** backend, with optimized performance using **Caffeine** for caching role-resource mappings. -->


### Prerequisites

Ensure you have the following installed:
- **Java 17+**
- **Maven**
- **MySQL**
- **Keycloak (v21 or later is recommended)**  
- Any REST client like **Postman** (optional, for testing)



### Step-by-Step Setup

#### 1. Install and Run Keycloak
You can download and run Keycloak using the following steps:

##### a. Download Keycloak  
Visit [https://www.keycloak.org/downloads](https://www.keycloak.org/downloads) and download the latest version.

##### b. Start Keycloak  
```bash
bin/kc.sh start-dev
```

This starts Keycloak in development mode on `http://localhost:8080`.

---

#### 2. Create a Realm

- Log in to the Keycloak Admin Console: [http://localhost:8080/admin](http://localhost:8080/admin)  
  Default credentials: `admin` / `admin` (or what you set during setup)

- Click on **"Create Realm"**
- Name it: `demo-realm`

---

#### 3. Create a Client

Within `demo-realm`:

- Go to **Clients** → **Create**
- **Client ID**: `spring-backend`
- **Client Protocol**: `openid-connect`
- **Root URL**: `http://localhost:8082`
- Click **Save**

Now configure the client:
- **Access Type**: `confidential`
- **Valid Redirect URIs**: `http://localhost:8082/*`
- **Web Origins**: `+` (all)
- Enable **Standard Flow** (Authorization Code Flow)
- Copy the **Client Secret** from the "Credentials" tab

---

#### 4. Create Roles and Users (Optional, for RBAC Demo)

- Go to **Users** → **Add User**
- Create a test user and set credentials (password)
- Assign **roles** or **realm roles** as needed
- You can use these roles later in the app for fine-grained access control

---

#### 5. Configure `application.yml` / `application.properties`

Below is the sample `application.yml` used in this application:

```yaml
server:
  port: 8082  # Port where your Spring Boot app will run

spring:
  datasource:
    url: jdbc:mysql://localhost:3306/<your-database-name>  # Replace with your MySQL DB name
    username: <your-db-username>                            # Replace with your MySQL username
    password: <your-db-password>                            # Replace with your MySQL password
    driver-class-name: com.mysql.cj.jdbc.Driver

  security:
    oauth2:
      client:
        registration:
          keycloak:
            client-id: <your-client-id>                     # e.g., "spring-backend"
            client-secret: "<your-client-secret>"           # Copied from Keycloak -> Clients -> Credentials tab
            authorization-grant-type: authorization_code
            scope: openid, profile, email
        provider:
          keycloak:
            issuer-uri: http://localhost:8080/realms/<your-realm-name>  # Replace with your realm name
            authorization-uri: http://localhost:8080/realms/<your-realm-name>/protocol/openid-connect/auth
            token-uri: http://localhost:8080/realms/<your-realm-name>/protocol/openid-connect/token
            user-info-uri: http://localhost:8080/realms/<your-realm-name>/protocol/openid-connect/userinfo
            jwk-set-uri: http://localhost:8080/realms/<your-realm-name>/protocol/openid-connect/certs

      resourceserver:
        jwt:
          issuer-uri: http://localhost:8080/realms/<your-realm-name>  # Same realm as above

jwt:
  auth:
    converter:
      resource-id: <your-client-id>                  # Should match the one under client.registration
      principle-attribute: preferred_username        # Keycloak claim used as principal (default is usually fine)

logging:
  level:
    org.springframework.security: DEBUG
    org.springframework.web: DEBUG
    org.springframework.security.oauth2: DEBUG

authentication-type: "implicit"  # Used internally to choose between implicit or authorization_code flows

```

>  The `authentication-type` field is used internally in the application to choose between implicit and authorization code flows.

---

#### 6. Create MySQL Database

Make sure MySQL is running and create a database:
```sql
CREATE DATABASE keycloak_trial;
```

Ensure your DB credentials match what’s configured in `application.yml`.

---

#### 7. Run the Application

Run the Spring Boot application using Maven:

```bash
mvn spring-boot:run
```

The backend will start on `http://localhost:8082`.

---
## Application Request Flow

Once the application is running and properly configured, the backend is protected using Spring Security and integrated with Keycloak for authentication and authorization. Here's a step-by-step flow of what happens when a request hits the backend:

### Request Handling Flow

1. **Spring Security Filters Triggered**  
   Every incoming request passes through custom filters configured using Spring Security.

2. **JWT Validation**  
   - The first check is to see if a **valid JWT access token** is present in the request header.
   - If **valid**, the user is authenticated and the request proceeds to authorization.
   - If **invalid**, the application attempts the next step.

3. **Refresh Token Check**
   - A call is made to Keycloak to verify if the **refresh token** is still valid.
   - If valid, a new JWT token is obtained from Keycloak and attached to the request.

4. **Redirect to Login**
   - If **both access and refresh tokens are invalid**, the user is redirected to the **Keycloak login page** for re-authentication.

5. **Authorization Filter**
   - After authentication is ensured, another filter checks if the **user is authorized to access the requested resource**.
   - This is done by checking the user's roles against a **role-resource mapping table**.

6. **Caching with Caffeine**
   - To avoid hitting the database for every request, the **role-resource table is cached** using the Caffeine library.
   - On cache miss, the DB is queried, otherwise the cached data is used.

7. **Access Granted or Denied**
   - If the user has the required role mapped to the resource, the request is allowed through.
   - Otherwise, an **unauthorized error (HTTP 403)** is returned.

8. **Login Endpoint Bypass**
   - The `/login` endpoint is explicitly configured in the security setup to **bypass all filters**, so users can access it without any token.

>  For a visual overview, refer to the state diagram here: [**State Chart**]({dbdigramlink})

---

## Authentication & RBAC APIs

The following endpoints have been implemented to support login, registration, role assignment, and logout functionality:

| **Endpoint**                  | **Method** | **Description**                              | **Request Params**                                                                                                            | **Response**                                             |
|------------------------------|------------|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------|
| `/api/auth/login`            | `GET`      | Starts login flow (code/password)            | Optional: `username`, `password`                                                                                              | Redirect or token cookies                               |
| `/api/auth/callback`         | `GET`      | Handles OAuth2 callback and sets cookies     | `code`                                                                                                                        | Redirect to frontend or `401` if error                  |
| `/api/auth/addUser`          | `POST`     | Adds new user (admin credentials)            | `adminUsername`, `adminPassword`, `newUsername`, `newPassword`, `newFirstName`, `newLastName`, `newEmail`                    | `200 OK` or `401 UNAUTHORIZED`                          |
| `/api/auth/register`         | `POST`     | Self-registration via client credentials     | `newUsername`, `newPassword`, `newFirstName`, `newLastName`, `newEmail`                                                      | `200 OK` or `401 UNAUTHORIZED`                          |
| `/api/auth/add-client-role`  | `POST`     | Creates a new client role in Keycloak        | `roleName`                                                                                                                    | `200 OK` or `401 UNAUTHORIZED`                          |

---

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
- Retrieves mapping of roles to resources ( cached in memory using caffeine).
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