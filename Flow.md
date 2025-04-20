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

| Endpoint                     | Description                                        |
|------------------------------|----------------------------------------------------|
| `POST /api/auth`            | Handles internal auth logic post token validation |
| `GET /login`                | Redirects to Keycloak login (publicly accessible)  |
| `POST /register`            | Registers a new user                               |
| `POST /addUser`             | Adds a user directly (admin functionality)         |
| `POST /add-client-role`     | Adds a new client role in Keycloak                 |
| `POST /assign-client-role`  | Assigns a role to a specific user                  |
| `POST /logout`              | Logs out the user and invalidates tokens           |

👉 **Note**: Request and response body formats for these APIs will be added in the next section.