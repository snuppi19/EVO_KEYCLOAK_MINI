package com.mtran.mvc.service;

import org.springframework.stereotype.Service;

@Service
public interface TokenService {
    void saveRefreshToken(String userEmail, String refreshToken);
    String getRefreshToken(String userEmail);
    void saveAccessToken(String userEmail, String accessToken);
    String getAccessToken(String userEmail);
}
