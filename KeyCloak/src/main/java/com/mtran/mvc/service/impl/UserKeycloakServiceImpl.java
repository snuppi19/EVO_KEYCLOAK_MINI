package com.mtran.mvc.service.impl;

import com.mtran.mvc.dto.response.TokenExchangeResponse;
import com.mtran.mvc.dto.request.*;
import com.mtran.mvc.dto.response.TokenResponse;
import com.mtran.mvc.dto.response.UserResponse;
import com.mtran.mvc.entity.KeycloakProperties;
import com.mtran.mvc.entity.Role.UserRole;
import com.mtran.mvc.entity.User;
import com.mtran.mvc.mapper.UserMapperKeycloak;
import com.mtran.mvc.repository.RoleRepository;
import com.mtran.mvc.repository.UserRepository;
import com.mtran.mvc.repository.UserRoleRepository;
import com.mtran.mvc.service.IdentityProviderService;
import com.mtran.mvc.service.UserKeycloakService;
import com.mtran.mvc.support.AppException;
import com.mtran.mvc.support.ErrorCode;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;


@Slf4j
@Service
@RequiredArgsConstructor
public class UserKeycloakServiceImpl implements UserKeycloakService {
    private final UserRepository userRepository;
    private final UserMapperKeycloak userMapperKeycloak;
    private final KeycloakProperties keycloakProperties;
    private final KeycloakIdentityProviderServiceImpl keycloakIdentityProvider;
    private final SelfIdentityProviderServiceImpl selfIdentityProvider;
    private final RoleServiceImpl roleService;
    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;
    private final TokenServiceImpl tokenServiceImpl;


    public Page<UserResponse> getAllProfiles(PagingRequest pagingRequest) {
        String keycloakId = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByKeycloakId(keycloakId);
        String accessToken = tokenServiceImpl.getAccessToken(user.getEmail());
        if (accessToken == null) {
            throw new AppException(ErrorCode.INVALID_KEY);
        }
        int page = pagingRequest.getPage();
        int size = pagingRequest.getSize();
        String sortBy = pagingRequest.getSortBy();
        boolean isDesc = pagingRequest.isDescending();

        Sort sort = isDesc ? Sort.by(sortBy).descending() : Sort.by(sortBy).ascending();
        Pageable pageable = PageRequest.of(page, size, sort);
        Page<User> users = userRepository.findAll(pageable);
        return users.map(userMapperKeycloak::toUserResponse);
    }

    private IdentityProviderService getIdentityProvider() {
        return keycloakProperties.isEnabled() ? keycloakIdentityProvider : selfIdentityProvider;
    }

    public void register(RegisterRequest request) {
        getIdentityProvider().register(request);
    }

    public String getLoginUrl() {
        return getIdentityProvider().getLoginUrl();
    }

    public TokenExchangeResponse handleCallback(String code) {
        return getIdentityProvider().handleCallback(code);
    }

    public void login(LoginRequest loginRequest) {
        getIdentityProvider().login(loginRequest);
    }

    public TokenResponse getTokensAfterLogin(String email) {
        return selfIdentityProvider.getTokensAfterLogin(email);
    }

    public TokenExchangeResponse refresh(RefreshRequest refreshRequestKeyCloak) {
        return getIdentityProvider().refreshToken(refreshRequestKeyCloak);
    }

    public UserResponse getUserProfileById(Integer id) {
        if (id <= 0) {
            throw new AppException(ErrorCode.ID_INVALID);
        }
        User user = userRepository.findById(id);
        if (user == null) {
            throw new AppException(ErrorCode.USER_NOT_FOUND);
        }
        if (keycloakProperties.isEnabled()) {
            return getIdentityProvider().getUserProfile(user.getKeycloakId());
        }
        return userMapperKeycloak.toUserResponse(user);
    }

    public void logout(LogoutRequest request) {
        getIdentityProvider().logout(request);
    }

    public ResponseEntity<?> changePassword(ChangePasswordRequest changePasswordRequest) {
        return getIdentityProvider().changePassword(changePasswordRequest);
    }

    public ResponseEntity<?> softDelete(DeleteRequest deleteRequest) {
        return getIdentityProvider().softDelete(deleteRequest);
    }

    public ResponseEntity<?> changeActiveStatus(ChangeActiveStatusRequest changeActiveStatusRequest) {
        return getIdentityProvider().changeActiveStatus(changeActiveStatusRequest);
    }

    public void assignRoleToUser(Integer userId, Integer roleId) {
        String keycloakId = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByKeycloakId(keycloakId);
        userRepository.findById(userId.toString())
                .orElseThrow(() -> new RuntimeException("User not found: " + userId));
        roleRepository.findById(roleId)
                .orElseThrow(() -> new RuntimeException("Role not found: " + roleId));
        if (!userRoleRepository.existsByUserIdAndRoleId(userId, roleId)) {
            UserRole userRole = new UserRole();
            userRole.setUserId(userId);
            userRole.setRoleId(roleId);
            userRoleRepository.save(userRole);
        }
    }

    @Transactional
    public void removeRoleFromUser(Integer userId, Integer roleId) {
        String keycloakId = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByKeycloakId(keycloakId);
        userRepository.findById(userId.toString())
                .orElseThrow(() -> new RuntimeException("User not found: " + userId));
        roleRepository.findById(roleId)
                .orElseThrow(() -> new RuntimeException("Role not found: " + roleId));
        if (userRoleRepository.existsByUserIdAndRoleId(userId, roleId)) {
           userRoleRepository.deleteByUserIdAndRoleId(userId, roleId);
        }else {
            throw new RuntimeException("Khong ton tai user co role nay");
        }
    }
}
