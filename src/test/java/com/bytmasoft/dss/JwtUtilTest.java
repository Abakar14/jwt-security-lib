package com.bytmasoft.dss;

import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JwtUtilTest {

private JwtUtil jwtUtil;
private SecretProvider secretProvider;

@BeforeEach
void setUp() {
	secretProvider = Mockito.mock(SecretProvider.class);
	jwtUtil = new JwtUtil(secretProvider);
}

@Test
void testGenerateAndValidateToken() {
	String username = "abakar";
	List<String> roles = List.of("ROLE_USER", "ROLE_ADMIN");

	String token = jwtUtil.generateAccessToken(username, roles);

	assertTrue(jwtUtil.validateAccessToken(token, username));
	assertEquals(username, jwtUtil.extractUsername(token));
	assertEquals(roles, jwtUtil.extractRoles(token));

	String refreshToken = jwtUtil.generateRefreshToken(username, roles);
	boolean isValid = jwtUtil.validateAccessToken(refreshToken, username);
	assertTrue(isValid, "Access token should be valid");
}

}