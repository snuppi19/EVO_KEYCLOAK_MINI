package com.mtran.mvc.service;

import com.mtran.mvc.dto.request.*;
import com.mtran.mvc.dto.response.TokenExchangeResponse;
import com.mtran.mvc.dto.response.TokenResponse;
import com.mtran.mvc.dto.response.UserResponse;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public interface UserKeycloakService {
    Page<UserResponse> getAllProfiles(PagingRequest pagingRequest);
    void register(RegisterRequest request);
    String getLoginUrl();
    TokenExchangeResponse handleCallback(String code);
    void login(LoginRequest loginRequest);
    TokenResponse getTokensAfterLogin(String email);
    TokenExchangeResponse refresh(RefreshRequest_keyCloak refreshRequestKeyCloak);
    UserResponse getUserProfileById(Integer id);
    void logout(LogoutRequest request);
    ResponseEntity<?> changePassword(ChangePasswordRequest changePasswordRequest);
    ResponseEntity<?> softDelete(DeleteRequest deleteRequest);
    ResponseEntity<?> changeActiveStatus(ChangeActiveStatusRequest changeActiveStatusRequest);
    void assignRoleToUser(Integer userId, Integer roleId);
    void removeRoleFromUser(Integer userId, Integer roleId);
}
