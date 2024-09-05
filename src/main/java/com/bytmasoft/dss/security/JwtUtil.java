package com.bytmasoft.dss.security;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {

    @Value("${jwt.secret.key}")
    private String secret;

    @Value("${jwt.access.token.expiration}")
    private Long accessTokenExpiration;

    @Value("${jwt.refresh.token.expiration}")
    private Long refreshTokenExpiration;

    public String generateAccessToken(String username, List<String> roles) {
        return createToken(Map.of("roles", roles), username, accessTokenExpiration);
    }

    public String generateRefreshToken(String username, List<String> roles) {
        return createToken(Map.of("roles", roles), username, refreshTokenExpiration);
    }

    private String createToken(Map<String, Object> claims, String username, Long expiration) {

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Boolean validateAccessToken(String token, String username) {

        try {
            final String extractUsername = extractUsername(token);
            return (extractUsername.equals(username) && !isTokenExpired(token));

        }catch (ExpiredJwtException ex ) {
            throw ex;
        }catch (Exception ex) {
            return false;
        }

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
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }


}
