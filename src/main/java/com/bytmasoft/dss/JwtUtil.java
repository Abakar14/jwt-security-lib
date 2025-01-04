package com.bytmasoft.dss;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.function.Function;

@Component
public class JwtUtil {

private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

private final SecretProvider secretProvider;

public JwtUtil(SecretProvider secretProvider) {
	this.secretProvider = secretProvider;
}

	@Value("${jwt.rsa.private-key}")
	private String privateKeyString;
/**
 *
 * @param username
 * @param roles
 * @param additionalClaims used for extern custom claims
 * @return
 */
public String generateAccessToken(String username, List<String> roles, Map<String, Object> additionalClaims) {
	Map<String, Object> claims = new HashMap<>(additionalClaims);
	claims.put("roles", roles);
	return generateToken(claims, username, this.secretProvider.getAaccessTokenExpiration());
}

/**
 * @Deprecated(since = "1.1.3", forRemoval = true)
 * @param username
 * @param roles
 * @return
 */
public String generateRefreshToken(String username, List<String> roles) {
	return generateToken(Map.of("roles", roles), username, this.secretProvider.getRefreshTokenExpiration());
}

/**
 *
 * @param refreshToken
 * @return new accessToken
 */
public String refreshAccessToken(String refreshToken) {
	if (refreshToken == null || refreshToken.isEmpty()) {
		throw new IllegalArgumentException("Refresh token cannot be null or empty");
	}
	if(!validateRefreshToken(refreshToken)) {
		throw new IllegalArgumentException("Invalid refresh token");
	}
	String username = extractUsername(refreshToken);
	List<String> roles = extractRoles(refreshToken);

	return generateToken(Map.of("roles", roles), username, this.secretProvider.getRefreshTokenExpiration());
}

private PrivateKey getPrivateKey() {
	try {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		byte[] keyBytes = Base64.getDecoder().decode(privateKeyString
				                                             .replaceAll("-----BEGIN PRIVATE KEY-----", "")
				                                             .replaceAll("-----END PRIVATE KEY-----", "")
				                                             .replaceAll("\\s+", ""));
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		return privateKey;

	} catch (NoSuchAlgorithmException e) {
		throw new RuntimeException(e);
	} catch (InvalidKeySpecException e) {
		throw new RuntimeException(e);
	}


}
private String generateToken(Map<String, Object> claims, String username, Long expiration) {


	return Jwts.builder()
			       .setClaims(claims)
			       .setSubject(username)
			       .setIssuedAt(new Date(System.currentTimeMillis()))
			       .setIssuer("http://localhost:8081")
			       .setExpiration(new Date(System.currentTimeMillis() + expiration))
			       .signWith(SignatureAlgorithm.RS256, this.getPrivateKey())
			       .compact();
}
public String extractUsername(String token) {
	return extractClaim(token, Claims::getSubject);
}

public Date extractIssuedAt(String token) {
	return extractClaim(token, Claims::getIssuedAt);
}

public Boolean validateAccessToken(String token, String username) {

	try {
		final String extractedUsername = extractUsername(token);
		logger.info("Validating access token for username: {}", extractedUsername);
		return (extractedUsername.equals(username) && !isTokenExpired(token));

	}catch (ExpiredJwtException ex ) {
		logger.warn("Token expired for username: {}", username, ex);
		return false;
	}catch (Exception ex) {
		logger.error("Token validation failed for username: {}", username, ex);
		return false;
	}

}

/**
 * Add support for RSA keys and dynamic decoder configuration
 * Support Asymmetric Cryptography
 * @return
 */
public JwtDecoder jwtDecoder() {
	RSAPublicKey publicKey = secretProvider.getPublicKey();
	return NimbusJwtDecoder.withPublicKey(publicKey).build();
}

/**
 * Support multiple issuers for multi-tenant or multi-service scenarios
 * @param issuer
 * @return
 */
public JwtDecoder createJwtDecoder(String issuer) {
	return JwtDecoders.fromIssuerLocation(issuer);
}



public Boolean validateRefreshToken(String token) {
	return !isTokenExpired(token);
}

public List<String> extractRoles(String token){
	return extractClaim(token, claims -> claims.get("roles", List.class));

}
public Date extractExpiration(String token) {
	return extractClaim(token, Claims::getExpiration);
}

public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
	final Claims claims = extractAllClaims(token);
	return claimsResolver.apply(claims);
}

private Claims extractAllClaims(String token) {
	return Jwts.parser().setSigningKey(secretProvider.getSecret()).parseClaimsJws(token).getBody();
}

private boolean isTokenExpired(String token) {
	return extractExpiration(token).before(new Date());
}

}
