
---
# Setup and Running the Application

This section will guide you through setting up the project and running it locally. The application demonstrates integration between **Keycloak** and a **Spring Boot** backend, with optimized performance using **Caffeine** for caching role-resource mappings.

---

## Prerequisites

Ensure you have the following installed:
- **Java 17+**
- **Maven**
- **MySQL**
- **Keycloak (v21 or later is recommended)**  
- Any REST client like **Postman** (optional, for testing)

---

## Step-by-Step Setup

### 1. Install and Run Keycloak
You can download and run Keycloak using the following steps:

#### a. Download Keycloak  
Visit [https://www.keycloak.org/downloads](https://www.keycloak.org/downloads) and download the latest version.

#### b. Start Keycloak  
```bash
bin/kc.sh start-dev
```

This starts Keycloak in development mode on `http://localhost:8080`.

---

### 2. Create a Realm

- Log in to the Keycloak Admin Console: [http://localhost:8080/admin](http://localhost:8080/admin)  
  Default credentials: `admin` / `admin` (or what you set during setup)

- Click on **"Create Realm"**
- Name it: `demo-realm`

---

### 3. Create a Client

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

### 4. Create Roles and Users (Optional, for RBAC Demo)

- Go to **Users** → **Add User**
- Create a test user and set credentials (password)
- Assign **roles** or **realm roles** as needed
- You can use these roles later in the app for fine-grained access control

---

### 5. Configure `application.yml` / `application.properties`

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

### 6. Create MySQL Database

Make sure MySQL is running and create a database:
```sql
CREATE DATABASE keycloak_trial;
```

Ensure your DB credentials match what’s configured in `application.yml`.

---

### 7. Run the Application

Run the Spring Boot application using Maven:

```bash
mvn spring-boot:run
```

The backend will start on `http://localhost:8082`.

---