package com.accolite.pru.health.AuthApp.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.accolite.pru.health.AuthApp.cache.LoggedOutJwtTokenCache;
import com.accolite.pru.health.AuthApp.event.OnUserLogoutSuccessEvent;
import com.accolite.pru.health.AuthApp.exception.InvalidTokenRequestException;

@ExtendWith(MockitoExtension.class)
public class JwtTokenValidatorTest {

    private static final String JWT_SECRET = "testSecret";
    private static final long JWT_EXPIRY_IN_MS = 25000;

    @Mock
    private LoggedOutJwtTokenCache loggedOutTokenCache;

    private JwtTokenProvider tokenProvider;

    private JwtTokenValidator tokenValidator;

    @BeforeEach
    public void setUp() {
        this.tokenProvider = new JwtTokenProvider(JWT_SECRET, JWT_EXPIRY_IN_MS);
        this.tokenValidator = new JwtTokenValidator(JWT_SECRET, loggedOutTokenCache);
    }

    @Test
    public void testValidateTokenThrowsExceptionWhenTokenIsDamaged() {
        String token = tokenProvider.generateTokenFromUserId(100L);
//        OnUserLogoutSuccessEvent logoutEvent = stubLogoutEvent("U1", token);
//        when(loggedOutTokenCache.getLogoutEventForToken(token)).thenReturn(logoutEvent);

        InvalidTokenRequestException thrown = assertThrows(InvalidTokenRequestException.class, () -> {
        	tokenValidator.validateToken(token + "-Damage");
        });
        assertThat(thrown.getMessage()).startsWith("Incorrect signature: ");
    }

    @Test
    public void testValidateTokenThrowsExceptionWhenTokenIsExpired() throws InterruptedException {
        String token = tokenProvider.generateTokenFromUserId(123L);
        TimeUnit.MILLISECONDS.sleep(JWT_EXPIRY_IN_MS);
//        OnUserLogoutSuccessEvent logoutEvent = stubLogoutEvent("U1", token);
//        when(loggedOutTokenCache.getLogoutEventForToken(token)).thenReturn(logoutEvent);

        InvalidTokenRequestException thrown = assertThrows(InvalidTokenRequestException.class, () -> {
        	tokenValidator.validateToken(token);
        });
        assertThat(thrown.getMessage()).startsWith("Token expired. Refresh required");
    }

    @Test
    public void testValidateTokenThrowsExceptionWhenItIsPresentInTokenCache() {
        String token = tokenProvider.generateTokenFromUserId(124L);
        OnUserLogoutSuccessEvent logoutEvent = stubLogoutEvent("U2", token);
        when(loggedOutTokenCache.getLogoutEventForToken(token)).thenReturn(logoutEvent);

        InvalidTokenRequestException thrown = assertThrows(InvalidTokenRequestException.class, () -> {
        	tokenValidator.validateToken(token);
        });
        assertThat(thrown.getMessage()).startsWith("Token corresponds to an already logged out user [U2]");
    }

    @Test
    public void testValidateTokenWorksWhenItIsNotPresentInTokenCache() {
        String token = tokenProvider.generateTokenFromUserId(100L);
        tokenValidator.validateToken(token);
        verify(loggedOutTokenCache, times(1)).getLogoutEventForToken(token);
    }

    private OnUserLogoutSuccessEvent stubLogoutEvent(String email, String token) {
        return new OnUserLogoutSuccessEvent(email, token, null);
    }
}
