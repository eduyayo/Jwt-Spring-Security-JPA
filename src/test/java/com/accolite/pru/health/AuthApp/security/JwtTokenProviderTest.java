package com.accolite.pru.health.AuthApp.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import com.accolite.pru.health.AuthApp.model.CustomUserDetails;
import com.accolite.pru.health.AuthApp.model.Role;
import com.accolite.pru.health.AuthApp.model.RoleName;
import com.accolite.pru.health.AuthApp.model.User;

@ExtendWith(MockitoExtension.class)
public class JwtTokenProviderTest {

    private static final String JWT_SECRET = "testSecret";
    private static final long JWT_EXPIRY_IN_MS = 25000;

    @InjectMocks
    private JwtTokenProvider tokenProvider;

    @BeforeEach
    public void setUp() {
    	ReflectionTestUtils.setField(tokenProvider, "jwtSecret", JWT_SECRET);
    	ReflectionTestUtils.setField(tokenProvider, "jwtExpirationInMs", JWT_EXPIRY_IN_MS);

    }

    @Test
    public void testGetUserIdFromJWT() {
        String token = tokenProvider.generateToken(stubCustomUser());
        assertThat(tokenProvider.getUserIdFromJWT(token).longValue()).isEqualTo(100);
    }

    @Test
    public void testGetExpiryDuration() {
    	assertThat(tokenProvider.getExpiryDuration()).isEqualTo(JWT_EXPIRY_IN_MS);
    }

    @Test
    public void testGetAuthoritiesFromJWT() {
        String token = tokenProvider.generateToken(stubCustomUser());
        assertThat(tokenProvider.getAuthoritiesFromJWT(token)).isNotNull();
    }

    private CustomUserDetails stubCustomUser() {
        User user = new User();
        user.setId((long) 100);
        user.setRoles(Collections.singleton(new Role(RoleName.ROLE_ADMIN)));
        return new CustomUserDetails(user);
    }

}
