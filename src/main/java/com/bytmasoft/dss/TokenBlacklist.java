package com.bytmasoft.dss;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.springframework.stereotype.Component;
import java.util.concurrent.TimeUnit;

/**
 * Add Token Revocation Support
 * Implement a mechanism for token revocation (e.g., blacklist or invalidation).
 * This is useful for logout scenarios or when access needs to be immediately revoked.
 */

@Component
public class TokenBlacklist {

private final Cache<String, Boolean> blacklist = CacheBuilder.newBuilder()
		                                                 .expireAfterWrite(7, TimeUnit.DAYS)
		                                                 .build();

public void addToBlacklist(String tokenId) {
	blacklist.put(tokenId, true);
}

public boolean isBlacklisted(String tokenId) {
	return blacklist.getIfPresent(tokenId) != null;
}

}
