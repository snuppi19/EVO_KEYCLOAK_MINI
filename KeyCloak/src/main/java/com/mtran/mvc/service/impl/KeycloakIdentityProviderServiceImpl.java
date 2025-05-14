package com.mtran.mvc.service.impl;

import com.mtran.mvc.dto.identity.Credential;
import com.mtran.mvc.dto.request.TokenExchangeParamRequest;
import com.mtran.mvc.dto.response.TokenExchangeResponse;
import com.mtran.mvc.dto.request.UserCreateParamRequest;
import com.mtran.mvc.dto.request.UserUpdateParamRequest;
import com.mtran.mvc.dto.request.*;
import com.mtran.mvc.dto.response.UserResponse;
import com.mtran.mvc.entity.KeycloakProperties;
import com.mtran.mvc.entity.Role.Role;
import com.mtran.mvc.entity.Role.UserRole;
import com.mtran.mvc.entity.User;
import com.mtran.mvc.mapper.UserMapperKeycloak;
import com.mtran.mvc.repository.IdentityClient;
import com.mtran.mvc.repository.RoleRepository;
import com.mtran.mvc.repository.UserRepository;
import com.mtran.mvc.repository.UserRoleRepository;
import com.mtran.mvc.service.IdentityProviderService;
import com.mtran.mvc.support.AppException;
import com.mtran.mvc.support.ErrorCode;
import feign.FeignException;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


@Service
@RequiredArgsConstructor
public class KeycloakIdentityProviderServiceImpl implements IdentityProviderService {
    private final KeycloakProperties keycloakProperties;
    private final IdentityClient identityClient;
    private final UserRepository userRepository;
    private final UserMapperKeycloak userMapperKeycloak;
    private final TokenServiceImpl tokenServiceImpl;
    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;

    @Override
    public void register(RegisterRequest request) {
        try {
            // Lấy token admin để tạo user trên Keycloak
            TokenExchangeResponse adminToken = identityClient.exchangeToken(TokenExchangeParamRequest.builder()
                    .grant_type("client_credentials")
                    .scope("openid")
                    .client_id(keycloakProperties.getClientId())
                    .client_secret(keycloakProperties.getClientSecret())
                    .build());

            // Tạo user trên Keycloak
            ResponseEntity<?> creationResponse = identityClient.createUser(
                    "Bearer " + adminToken.getAccessToken(),
                    UserCreateParamRequest.builder()
                            .firstName(request.getName())
                            .email(request.getEmail())
                            .enabled(true)
                            .emailVerified(false)
                            .credentials(java.util.List.of(Credential.builder()
                                    .type("password")
                                    .temporary(false)
                                    .value(request.getPassword())
                                    .build()))
                            .build());

            // Lấy Keycloak ID từ response
            String keycloakId = extractUserId(creationResponse);

            // Lưu user vào database nội bộ
            User user = userMapperKeycloak.toUser(request);
            user.setKeycloakId(keycloakId);
            user.setPasswordSynced(true);
            PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(15);
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            userRepository.save(user);
            UserRole userRole = new UserRole();
            userRole.setUserId(user.getId());
            Role role = roleRepository.findByRoleNameIgnoreCase("USER");
            userRole.setRoleId(role.getRoleId());
            userRoleRepository.save(userRole);
        } catch (FeignException e) {
            throw new AppException(ErrorCode.REGISTER_FAILD);
        }
    }

    private String extractUserId(ResponseEntity<?> response) {
        String location = response.getHeaders().get("Location").get(0);
        String[] split = location.split("/");
        return split[split.length - 1];
    }

    @Override
    public String getLoginUrl() {
        return String.format("%s/realms/%s/protocol/openid-connect/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=openid",
                keycloakProperties.getAuthServerUrl(),
                keycloakProperties.getRealm(),
                keycloakProperties.getClientId(),
                keycloakProperties.getRedirectUri());
    }

    @Override
    public TokenExchangeResponse handleCallback(String code) {
        try {
            TokenExchangeResponse token = identityClient.exchangeToken(TokenExchangeParamRequest.builder()
                    .grant_type("authorization_code")
                    .client_id(keycloakProperties.getClientId())
                    .client_secret(keycloakProperties.getClientSecret())
                    .code(code)
                    .redirect_uri(keycloakProperties.getRedirectUri())
                    .scope("openid")
                    .build());

            // Lưu refresh token vào Redis
            String email = extractEmailFromToken(token.getAccessToken());
            tokenServiceImpl.saveRefreshToken(email, token.getRefreshToken());
            tokenServiceImpl.saveAccessToken(email, token.getAccessToken());
            return token;
        } catch (Exception e) {
            throw new AppException(ErrorCode.CANT_CALLBACK);
        }
    }

    private String extractEmailFromToken(String accessToken) throws Exception {
        String publicKeyPEM = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzVVEQFu4gvR5gbC3QFwEeUp4NzwyoiSHVtwR5H5eMA59dJ0r1AYVhd6aq3mHmCS13eyg18Xmmp0b2PNvSPyr2M13IFfXuMe+0FM6uLuZcB4xxj9IAPooOSN9cmT9Xr0hx54fa0mK2JJ6JDSyvraLUX2YdrIDOkYydVUx0fUgdnvEoATEjdTbd4blBR0iu07ncTYPHrL14OGt7nQcl65Gv88jMSj60ugqVIip9yc6qBYDxjEaI4MZdVDemycOTn9mM2i1K9zR7Ua+lJULByzhNrSriGmoMHyTplIvYL9iq8oZ8bNcbNW8SDRWIL6IGC2kufYAj3b8Ti4+pCC1a4qIFQIDAQAB";
        PublicKey publicKey = getPublicKeyFromPEM(publicKeyPEM);
        return Jwts.parser()
                .setSigningKey(publicKey)
                .parseClaimsJws(accessToken)
                .getBody()
                .get("email", String.class);
    }

    public PublicKey getPublicKeyFromPEM(String pem) throws Exception {
        String publicKeyPEM = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\n", "")
                .replaceAll("\\s", "");
        byte[] decodedKey = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    @Override
    public void login(LoginRequest loginRequest) {
        String email = loginRequest.getEmail();
        String password = loginRequest.getPassword();

        if (email == null || email.isBlank()) {
            throw new AppException(ErrorCode.EMAIL_INVALID);
        }
        if (password == null || password.isBlank()) {
            throw new AppException(ErrorCode.PASSWORD_INVALID);
        }

        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw new AppException(ErrorCode.USER_NOT_FOUND);
        }
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(15);
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new AppException(ErrorCode.PASSWORD_INVALID);
        }
    }

    @Override
    public TokenExchangeResponse refreshToken(RefreshRequest refreshRequestKeyCloak) {
        String storedRefreshToken = tokenServiceImpl.getRefreshToken(refreshRequestKeyCloak.getEmail());
        String storedAccessToken = tokenServiceImpl.getAccessToken(refreshRequestKeyCloak.getEmail());
        if (storedRefreshToken == null) {
            throw new AppException(ErrorCode.REFRESH_TOKEN_NOT_FOUND);
        }

        try {
            TokenExchangeResponse tokenResponse = identityClient.exchangeToken(TokenExchangeParamRequest.builder()
                    .grant_type("refresh_token")
                    .client_id(keycloakProperties.getClientId())
                    .client_secret(keycloakProperties.getClientSecret())
                    .refresh_token(storedRefreshToken)
                    .scope("openid")
                    .build());
            if (storedAccessToken != null) {
                identityClient.logout("Bearer " + storedAccessToken,
                        TokenExchangeParamRequest.builder()
                                .client_id(keycloakProperties.getClientId())
                                .client_secret(keycloakProperties.getClientSecret())
                                .refresh_token(storedRefreshToken)
                                .build());
            }
            //xoa access token va refresh token cu di
            tokenServiceImpl.saveAccessToken(refreshRequestKeyCloak.getEmail(), null);
            tokenServiceImpl.saveRefreshToken(refreshRequestKeyCloak.getEmail(), null);
            //luu access token moi va refresh token moi
            tokenServiceImpl.saveRefreshToken(refreshRequestKeyCloak.getEmail(), tokenResponse.getRefreshToken());
            tokenServiceImpl.saveAccessToken(refreshRequestKeyCloak.getEmail(), tokenResponse.getAccessToken());
            return tokenResponse;
        } catch (FeignException e) {
            throw new AppException(ErrorCode.TOKEN_GENERATION_FAILED);
        }
    }

    @Override
    public UserResponse getUserProfile(String keycloakId) {
        String keycloakIdCheck = SecurityContextHolder.getContext().getAuthentication().getName();
        User userCheck = userRepository.findByKeycloakId(keycloakIdCheck);
        String accessToken = tokenServiceImpl.getAccessToken(userCheck.getEmail());
        if (accessToken == null) {
            throw new AppException(ErrorCode.INVALID_KEY);
        }
        User user = userRepository.findByKeycloakId(keycloakId);
        if (user == null) {
            throw new AppException(ErrorCode.USER_NOT_FOUND);
        }
        //đoạn này em không config ném được custome attribute lên keycloak nên tạm trỏ vào database
        return userMapperKeycloak.toUserResponse(user);
    }

    @Override
    public void logout(LogoutRequest request) {
        try {
            TokenExchangeResponse adminToken = identityClient.exchangeToken(TokenExchangeParamRequest.builder()
                    .grant_type("client_credentials")
                    .scope("openid")
                    .client_id(keycloakProperties.getClientId())
                    .client_secret(keycloakProperties.getClientSecret())
                    .build());
            identityClient.logout("Bearer " + adminToken.getAccessToken(),
                    TokenExchangeParamRequest.builder()
                            .client_id(keycloakProperties.getClientId())
                            .client_secret(keycloakProperties.getClientSecret())
                            .refresh_token(request.getRefreshToken())
                            .build());
            String email = extractEmailFromToken(request.getToken());
            tokenServiceImpl.saveRefreshToken(email, null);
            tokenServiceImpl.saveAccessToken(email, null);
        } catch (Exception e) {
            throw new AppException(ErrorCode.LOGOUT_FAILED);
        }
    }

    @Override
    public ResponseEntity<?> changePassword(ChangePasswordRequest changePasswordRequest) {
        try {
            String email = changePasswordRequest.getUser().getEmail();
            String oldPassword = changePasswordRequest.getUser().getPassword();
            String newPassword = changePasswordRequest.getNewPassword();
            User user = userRepository.findByEmail(email);
            if (user == null) {
                throw new AppException(ErrorCode.USER_NOT_FOUND);
            }
            PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(15);
            if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
                throw new AppException(ErrorCode.PASSWORD_INVALID);
            }
            TokenExchangeResponse adminToken = identityClient.exchangeToken(TokenExchangeParamRequest.builder()
                    .grant_type("client_credentials")
                    .scope("openid")
                    .client_id(keycloakProperties.getClientId())
                    .client_secret(keycloakProperties.getClientSecret())
                    .build());
            ResponseEntity<?> response = identityClient.resetPassword(
                    "Bearer " + adminToken.getAccessToken(),
                    keycloakProperties.getRealm(),
                    user.getKeycloakId(),
                    Credential.builder()
                            .type("password")
                            .temporary(false)
                            .value(newPassword)
                            .build()
            );
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);
            String accessToken = tokenServiceImpl.getAccessToken(email);
            String refreshToken = tokenServiceImpl.getRefreshToken(email);
            LogoutRequest logoutRequest = new LogoutRequest();
            if (accessToken != null && refreshToken != null) {
                logoutRequest.setToken(accessToken);
                logoutRequest.setRefreshToken(refreshToken);
                logoutRequest.setEmail(email);
                logout(logoutRequest);
            }
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            throw new AppException(ErrorCode.CHANGE_PASSWORD_FAILED);
        }
    }

    @Override
    public ResponseEntity<?> softDelete(DeleteRequest deleteRequest) {
        try {
            String email = deleteRequest.getUser().getEmail();
            User user = userRepository.findByEmail(email);
            if (user == null) {
                throw new AppException(ErrorCode.USER_NOT_FOUND);
            }
            userRepository.delete(user);
            keycloakBlockUser(email, false);
            return ResponseEntity.ok().body("User soft deleted successfully");
        } catch (Exception e) {
            throw new AppException(ErrorCode.DELETE_USER_FAILED);
        }
    }

    @Override
    public ResponseEntity<?> changeActiveStatus(ChangeActiveStatusRequest changeActiveStatusRequest) {
        try {
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
                keycloakBlockUser(email, activeStatus);
            }
            return ResponseEntity.ok().body("User change active status successfully");
        } catch (Exception e) {
            throw new AppException(ErrorCode.CHANGE_ACTIVE_STATUS_FAILED);
        }
    }

    private void keycloakBlockUser(String email, boolean status) {
        User user = userRepository.findByEmail(email);
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
        String accessToken = tokenServiceImpl.getAccessToken(email);
        String refreshToken = tokenServiceImpl.getRefreshToken(email);
        LogoutRequest logoutRequest = new LogoutRequest();
        if (accessToken != null && refreshToken != null) {
            logoutRequest.setToken(accessToken);
            logoutRequest.setRefreshToken(refreshToken);
            logoutRequest.setEmail(email);
            logout(logoutRequest);
        }
    }
}
