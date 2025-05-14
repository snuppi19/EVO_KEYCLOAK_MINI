package com.mtran.mvc.service;

import com.mtran.mvc.dto.response.TokenExchangeResponse;
import com.mtran.mvc.dto.request.*;
import com.mtran.mvc.dto.response.UserResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public interface IdentityProviderService {
    void register(RegisterRequest request);
    String getLoginUrl();
    TokenExchangeResponse handleCallback(String code);
    void login(LoginRequest loginRequest);
    TokenExchangeResponse refreshToken(RefreshRequest_keyCloak refreshRequestKeyCloak);
    UserResponse getUserProfile(String keycloakId);
    void logout(LogoutRequest request);
    ResponseEntity<?> changePassword(ChangePasswordRequest changePasswordRequest);
    ResponseEntity<?> softDelete(DeleteRequest deleteRequest);
    ResponseEntity<?> changeActiveStatus(ChangeActiveStatusRequest changeActiveStatusRequest);
}
