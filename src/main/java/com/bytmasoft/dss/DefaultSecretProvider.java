package com.bytmasoft.dss;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPublicKey;

/*@Component
public class DefaultSecretProvider implements SecretProvider {

@Value("${jwt.secret.key}")
private String secret;

@Value("${jwt.access.token.expiration}")
private Long accessTokenExpiration;

@Value("${jwt.refresh.token.expiration}")
private Long refreshTokenExpiration;

@Value("${jwt.access.rsa.public.key}")
RSAPublicKey rsaPublicKey;

@Override
public String getSecret() {
	return secret;
}

@Override
public Long getAaccessTokenExpiration() {
	return accessTokenExpiration;
}

@Override
public Long getRefreshTokenExpiration() {
	return refreshTokenExpiration;
}

@Override
public RSAPublicKey getPublicKey() {
	return null;
}
}*/
