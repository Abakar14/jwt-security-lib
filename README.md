# Security Library use for checking token from Client side
# JWT Security Library Documentation

The `jwt-security-lib` is a reusable library designed to handle JWT (JSON Web Token) operations such as token generation, validation, and claims extraction. It centralizes JWT-related logic for microservices, promoting consistency and reducing duplication.

## Features

- Generate access and refresh tokens.
- Validate access and refresh tokens.
- Extract claims, including username and roles.
- Configurable token expiration times and secret keys.
- Lightweight and easily integrable into Spring Boot applications.

## Dependencies

To use `jwt-security-lib`, ensure the following dependencies are added to your project:

```groovy
implementation 'org.springframework.boot:spring-boot-starter-web'
implementation 'org.springframework.boot:spring-boot-starter-security'
implementation 'org.springframework.boot:spring-boot-starter-oauth2-resource-server'
implementation group: 'io.jsonwebtoken', name: 'jjwt-api', version: '0.11.5'
runtimeOnly group: 'io.jsonwebtoken', name: 'jjwt-impl', version: '0.11.5'
runtimeOnly group: 'io.jsonwebtoken', name: 'jjwt-jackson', version: '0.11.5'
```

## Configuration

### Application Configuration

Define the following properties in your `application.yaml`:

```yaml
jwt:
  secret:
    key: "secure-key" # Your secure secret key
  access:
    token:
      expiration: 1800000 # 30 minutes in milliseconds
  refresh:
    token:
      expiration: 604800000 # 7 days in milliseconds
```

Alternatively, these can be provided via environment variables:

```bash
export JWT_SECRET_KEY="secure-key"
export JWT_ACCESS_TOKEN_EXPIRATION=1800000
export JWT_REFRESH_TOKEN_EXPIRATION=604800000
```

### Adding the Library

Include the `jwt-security-lib` as a dependency in your services:

```groovy
implementation project(':jwt-security-lib')
```

## Usage

### 1. Token Generation

Use the `JwtUtil` class to generate access and refresh tokens:

```java
@Autowired
private JwtUtil jwtUtil;

String username = "john.doe";
List<String> roles = List.of("ROLE_USER", "ROLE_ADMIN");

String accessToken = jwtUtil.generateAccessToken(username, roles);
String refreshToken = jwtUtil.generateRefreshToken(username, roles);
```

### 2. Token Validation

Validate tokens before processing requests:

```java
String token = "eyJhbGciOiJI...";
String username = "john.doe";

boolean isValid = jwtUtil.validateAccessToken(token, username);
if (isValid) {
    // Proceed with the request
}
```

### 3. Claims Extraction

Extract specific claims from the token:

```java
String username = jwtUtil.extractUsername(token);
List<String> roles = jwtUtil.extractRoles(token);
```

### 4. Customizing Configuration

You can dynamically set the secret key and expiration times:

```java
jwtUtil.setSecret("new-secret-key");
jwtUtil.setAccessTokenExpiration(3600000L); // 1 hour
jwtUtil.setRefreshTokenExpiration(1209600000L); // 14 days
```

## Security Configuration Integration

Use the library with `@EnableMethodSecurity` and Spring Security:

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/**").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt()
            );
        return http.build();
    }
}
```

## Testing

### Example JUnit Test

Ensure the library behaves as expected:

```java
@SpringBootTest
class JwtUtilTest {

    @Autowired
    private JwtUtil jwtUtil;

    @Test
    void testGenerateAndValidateAccessToken() {
        String username = "testuser";
        List<String> roles = List.of("ROLE_USER");

        String token = jwtUtil.generateAccessToken(username, roles);
        assertTrue(jwtUtil.validateAccessToken(token, username));

        String extractedUsername = jwtUtil.extractUsername(token);
        assertEquals(username, extractedUsername);
    }
}
```

## Enhancements

1. **Centralized Configuration**:
   Use a Config Server (e.g., Spring Cloud Config) to share `jwt` properties across services.
2. **Caching**:
   Implement caching for token validation to reduce redundant cryptographic operations.
3. **Custom Claims**:
   Extend the library to support additional claims as needed.
4. **Token Revocation**:
   Implement a mechanism to revoke tokens if required.

## FAQ

### Q: How secure is the library?

The library uses `HS512` for token signing, which is a secure HMAC algorithm. Ensure your secret key is strong and stored securely.

### Q: Can I use RSA algorithms?

Yes. Modify the `JwtUtil` class to use public/private keys for signing and verification.

### Q: Is the library compatible with Spring Security?

Yes. It integrates seamlessly with Spring Security and `oauth2ResourceServer`.

## Support

For questions or issues, contact the `jwt-security-lib` team at [support@bytmasoft.com](mailto\:support@bytmasoft.com) or
private email [abakar61@web.de](mailto\:abakar61@web.de).
please do not hesitate to contact me if you have any questions.



