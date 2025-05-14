package com.mtran.mvc.service.impl;

import com.mtran.mvc.config.utils.jwt.JwtUtil;
import com.mtran.mvc.dto.request.TokenExchangeParamRequest;
import com.mtran.mvc.dto.response.TokenExchangeResponse;
import com.mtran.mvc.dto.request.UserUpdateParamRequest;
import com.mtran.mvc.dto.request.*;
import com.mtran.mvc.dto.response.TokenResponse;
import com.mtran.mvc.dto.response.UserResponse;
import com.mtran.mvc.entity.KeycloakProperties;
import com.mtran.mvc.entity.User;
import com.mtran.mvc.mapper.UserMapperKeycloak;
import com.mtran.mvc.repository.IdentityClient;
import com.mtran.mvc.repository.UserRepository;
import com.mtran.mvc.service.IdentityProviderService;
import com.mtran.mvc.service.UserIamService;
import com.mtran.mvc.service.email.EmailSenderService;
import com.mtran.mvc.support.AppException;
import com.mtran.mvc.support.ErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class SelfIdentityProviderServiceImpl implements IdentityProviderService {
    private final UserRepository userRepository;
    private final UserMapperKeycloak userMapperKeycloak;
    private final JwtUtil jwtUtil;
    private final TokenServiceImpl tokenServiceImpl;
    private final EmailSenderService emailSenderService;
    private final com.mtran.mvc.service.email.OtpService OtpService;
    private final UserIamService userIamService;
    private final IdentityClient identityClient;
    private final KeycloakProperties keycloakProperties;

    @Override
    public void register(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()) != null) {
            throw new AppException(ErrorCode.EMAIL_EXISTS);
        }
        String otp = OtpService.generateOtp(request.getEmail());
        emailSenderService.sendEmail(request.getEmail(), "Mã xác thực OTP", "Mã OTP của bạn là: " + otp);
    }

    @Override
    public String getLoginUrl() {
        return null;
    }

    @Override
    public TokenExchangeResponse handleCallback(String code) {
        throw new AppException(ErrorCode.CANT_CALLBACK);
    }

    @Override
    public void login(LoginRequest loginRequest) {
        User user = userRepository.findByEmail(loginRequest.getEmail());
        if (user == null) {
            throw new AppException(ErrorCode.EMAIL_NOT_FOUND);
        }
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(15);
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword()) && !loginRequest.getPassword().equals(user.getPassword())) {
            throw new AppException(ErrorCode.PASSWORD_INVALID);
        }
        try {
            String accessToken = jwtUtil.generateToken(user.getEmail());
            String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());
            tokenServiceImpl.saveAccessToken(user.getEmail(), accessToken);
            tokenServiceImpl.saveRefreshToken(user.getEmail(), refreshToken);
        } catch (Exception e) {
            throw new AppException(ErrorCode.TOKEN_GENERATION_FAILED);
        }
    }

    public TokenResponse getTokensAfterLogin(String email) {
        String accessToken = tokenServiceImpl.getAccessToken(email);
        String refreshToken = tokenServiceImpl.getRefreshToken(email);
        if (accessToken == null || refreshToken == null) {
            throw new AppException(ErrorCode.TOKEN_GENERATION_FAILED);
        }
        return new TokenResponse(accessToken, refreshToken);
    }

    @Override
    public TokenExchangeResponse refreshToken(RefreshRequest refreshRequestKeyCloak) {
        String refreshToken = tokenServiceImpl.getRefreshToken(refreshRequestKeyCloak.getEmail());
        if (refreshToken == null) {
            throw new AppException(ErrorCode.REFRESH_TOKEN_NOT_FOUND);
        }
        try {
            //kiểm tra cả refresh và access có hiệu lực không rồi sinh ra access mới (qua validate token trong refresh)
            String accessTokenNEW = jwtUtil.refreshToken(refreshRequestKeyCloak);
            tokenServiceImpl.saveAccessToken(refreshRequestKeyCloak.getEmail(), accessTokenNEW);
            return new TokenExchangeResponse(accessTokenNEW, refreshToken);
        } catch (Exception e) {
            throw new AppException(ErrorCode.TOKEN_GENERATION_FAILED);
        }
    }

    @Override
    public UserResponse getUserProfile(String email) {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw new AppException(ErrorCode.USER_NOT_FOUND);
        }
        return userMapperKeycloak.toUserResponse(user);
    }

    @Override
    public void logout(LogoutRequest request) {
        try {
            String email = jwtUtil.extractEmail(request.getRefreshToken());
            tokenServiceImpl.saveRefreshToken(email, null);
            tokenServiceImpl.saveAccessToken(email, null);
            jwtUtil.logout(request);
        } catch (Exception e) {
            throw new AppException(ErrorCode.LOGOUT_FAILED);
        }
    }

    @Override
    public ResponseEntity<?> changePassword(ChangePasswordRequest changePasswordRequest) {
        userIamService.changePassword(changePasswordRequest.getUser().getEmail(),
                changePasswordRequest.getUser().getPassword(),
                changePasswordRequest.getNewPassword());
        // Luu thoi gian password bi doi
        userIamService.updateLastChangePassword(changePasswordRequest.getUser().getEmail(), LocalDateTime.now());
        String token = changePasswordRequest.getToken();
        String refreshToken = changePasswordRequest.getRefreshToken();

        if (token != null || refreshToken != null) {
            LogoutRequest logoutRequest = new LogoutRequest();
            logoutRequest.setToken(token);
            logoutRequest.setRefreshToken(refreshToken);
            try {
                jwtUtil.logout(logoutRequest);
            } catch (Exception e) {
                log.info("Token không hợp lệ : {}", e.getMessage());
            }
        }
        return ResponseEntity.ok("User thay đổi mật khẩu thành công !");
    }

    @Override
    public ResponseEntity<?> softDelete(DeleteRequest deleteRequest) {
        String email = deleteRequest.getUser().getEmail();
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw new AppException(ErrorCode.USER_NOT_FOUND);
        }
        userRepository.delete(user);
        blockUSER(email, false);
        return ResponseEntity.ok("User soft delete sucesssfully !");
    }

    @Override
    public ResponseEntity<?> changeActiveStatus(ChangeActiveStatusRequest changeActiveStatusRequest) {
        String email = changeActiveStatusRequest.getUser().getEmail();
        boolean activeStatus = changeActiveStatusRequest.getIsActive();
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw new AppException(ErrorCode.USER_NOT_FOUND);
        }

        if (user.isActive() == activeStatus) {
            return ResponseEntity.ok("User already same status!");
        } else {
            user.setActive(activeStatus);
            userRepository.save(user);
        }

        if (!activeStatus) {
            blockUSER(email, false);
        }
        return ResponseEntity.ok("User change status sucesssfully !");
    }

    private void blockUSER(String email, boolean status) {
        User user = userRepository.findByEmail(email);
        String accessToken = tokenServiceImpl.getAccessToken(email);
        String refreshToken = tokenServiceImpl.getRefreshToken(email);
        if(accessToken != null && refreshToken != null){
            LogoutRequest logoutRequest = new LogoutRequest();
            logoutRequest.setToken(accessToken);
            logoutRequest.setRefreshToken(refreshToken);
            try {
                jwtUtil.logout(logoutRequest);
            } catch (Exception e) {
                throw new AppException(ErrorCode.INVALID_KEY);
            }
        }
        //vo hieu hoa user tren keycloak ngay lap tuc
        TokenExchangeResponse adminToken = identityClient.exchangeToken(TokenExchangeParamRequest.builder()
                .grant_type("client_credentials")
                .scope("openid")
                .client_id(keycloakProperties.getClientId())
                .client_secret(keycloakProperties.getClientSecret())
                .build());

        identityClient.ChangeStatusUser(
                "Bearer " + adminToken.getAccessToken(),
                keycloakProperties.getRealm(),
                user.getKeycloakId(),
                UserUpdateParamRequest.builder()
                        .enabled(status)
                        .build()
        );
    }


}

