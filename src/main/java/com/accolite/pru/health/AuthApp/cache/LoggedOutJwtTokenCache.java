package com.accolite.pru.health.AuthApp.cache;

import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.accolite.pru.health.AuthApp.event.OnUserLogoutSuccessEvent;
import com.accolite.pru.health.AuthApp.security.JwtTokenProvider;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import net.jodah.expiringmap.ExpiringMap;

/**
 * This cache helps maintain a state to invalidate tokens post a successful logout operation.
 * Since JWT tokens are immutable, they'd still remain accessible post logout as long as the token
 * doesn't expire.
 * <p>
 * Note: To prevent this cache from building up indefinitely, we set a max size. The TTL for each
 * token will be the number of seconds that remain until its expiry. This is done as an optimization
 * as once a JWT token expires, it cannot be used anyway.
 */
@Component
@RequiredArgsConstructor
public class LoggedOutJwtTokenCache {

    private static final Logger logger = Logger.getLogger(LoggedOutJwtTokenCache.class);

    @Getter(lazy = true)
    private final ExpiringMap<String, OnUserLogoutSuccessEvent> tokenEventMap = ExpiringMap.builder()
          .variableExpiration()
          .maxSize(maxSize)
          .build();

    private final JwtTokenProvider tokenProvider;

    @Value("${app.cache.logoutToken.maxSize}")
    private final int maxSize;

    public void markLogoutEventForToken(OnUserLogoutSuccessEvent event) {
        String token = event.getToken();
        if (getTokenEventMap().containsKey(token)) {
            logger.info(String.format("Log out token for user [%s] is already present in the cache", event.getUserEmail()));

        } else {
            Date tokenExpiryDate = tokenProvider.getTokenExpiryFromJWT(token);
            long ttlForToken = getTTLForToken(tokenExpiryDate);
            logger.info(String.format("Logout token cache set for [%s] with a TTL of [%s] seconds. Token is due expiry at [%s]", event.getUserEmail(), ttlForToken, tokenExpiryDate));
            getTokenEventMap().put(token, event, ttlForToken, TimeUnit.SECONDS);
        }
    }

    public OnUserLogoutSuccessEvent getLogoutEventForToken(String token) {
        return getTokenEventMap().get(token);
    }

    private long getTTLForToken(Date date) {
        long secondAtExpiry = date.toInstant().getEpochSecond();
        long secondAtLogout = Instant.now().getEpochSecond();
        return Math.max(0, secondAtExpiry - secondAtLogout);
    }
}
