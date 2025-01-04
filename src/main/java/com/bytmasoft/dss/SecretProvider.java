package com.bytmasoft.dss;

import java.security.interfaces.RSAPublicKey;

public interface SecretProvider {
	String getSecret();
	Long getAaccessTokenExpiration();
	Long getRefreshTokenExpiration();
	RSAPublicKey getPublicKey();
}
