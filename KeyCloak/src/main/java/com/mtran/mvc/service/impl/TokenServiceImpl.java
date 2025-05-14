package com.mtran.mvc.service.impl;

import com.mtran.mvc.service.TokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class TokenServiceImpl implements TokenService {
    private final RedisTemplate<String, String> redisTemplate;
    private static final long ACCESS_TOKEN_EXPIRATION_TIME = 3600_000; // 1 giờ
    private static final long REFRESH_TOKEN_EXPIRATION_TIME = 7 * 24 * 3600_000; // 7 ngày

    public TokenServiceImpl(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }


    //refresh token
    public void saveRefreshToken(String userEmail, String refreshToken) {
        if (refreshToken == null) {
            redisTemplate.delete("refresh_token:" + userEmail);
        } else {
            redisTemplate.opsForValue().set("refresh_token:" + userEmail, refreshToken,
                    REFRESH_TOKEN_EXPIRATION_TIME, TimeUnit.MILLISECONDS);
        }
    }

    public String getRefreshToken(String userEmail) {
        return redisTemplate.opsForValue().get("refresh_token:" + userEmail);
    }

    //access token
    public void saveAccessToken(String userEmail, String accessToken) {
        if (accessToken == null) {
            redisTemplate.delete("access_token:" + userEmail);
        } else {
            redisTemplate.opsForValue().set("access_token:" + userEmail, accessToken,
                    ACCESS_TOKEN_EXPIRATION_TIME, TimeUnit.MILLISECONDS);
        }
    }

    public String getAccessToken(String userEmail) {
        return redisTemplate.opsForValue().get("access_token:" + userEmail);
    }


}
