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
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

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
    private final RoleHierarchy roleHierarchy;
    private final TokenServiceImpl tokenServiceImpl;


    public Page<UserResponse> getAllProfiles(PagingRequest pagingRequest) {
        String keycloakId = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByKeycloakId(keycloakId);
        String accessToken = tokenServiceImpl.getAccessToken(user.getEmail());
        if (accessToken == null) {
            throw new AppException(ErrorCode.INVALID_KEY);
        }
        checkPermission(user.getId(), "VIEW_ALL_USERS_PROFILE");

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
        String keycloakId = SecurityContextHolder.getContext().getAuthentication().getName();
        User userCheck = userRepository.findByKeycloakId(keycloakId);
        // Kiểm tra quyền
        checkPermission(userCheck.getId(), "VIEW_USER_PROFILE");
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
        String keycloakId = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByKeycloakId(keycloakId);
        // Kiểm tra quyền
        checkPermission(user.getId(), "RESET_PASSWORD");
        return getIdentityProvider().changePassword(changePasswordRequest);
    }

    public ResponseEntity<?> softDelete(DeleteRequest deleteRequest) {
        String keycloakId = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByKeycloakId(keycloakId);
        checkPermission(user.getId(), "CHANGE_USER_STATUS");
        // Kiểm tra quyền
        checkPermission(user.getId(), "SOFT_DELETE_USER");
        return getIdentityProvider().softDelete(deleteRequest);
    }

    public ResponseEntity<?> changeActiveStatus(ChangeActiveStatusRequest changeActiveStatusRequest) {
        String keycloakId = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByKeycloakId(keycloakId);
        checkPermission(user.getId(), "CHANGE_USER_STATUS");
        return getIdentityProvider().changeActiveStatus(changeActiveStatusRequest);
    }

    private void checkPermission(Integer userId, String requiredPermission) {
        List<String> roles = roleService.getRolesByUserId(userId);
        // Chuyển đổi vai trò thành GrantedAuthority
        List<SimpleGrantedAuthority> authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
        // Áp dụng RoleHierarchy để lấy tất cả quyền kế thừa
        List<SimpleGrantedAuthority> reachableAuthorities = roleHierarchy.getReachableGrantedAuthorities(authorities)
                .stream()
                .map(auth -> new SimpleGrantedAuthority(auth.getAuthority()))
                .collect(Collectors.toList());
        // Lấy danh sách quyền từ các vai trò (bao gồm quyền kế thừa)
        List<String> permissions = reachableAuthorities.stream()
                .map(auth -> roleService.getPermissionsByRoleName(auth.getAuthority().replace("ROLE_", "")))
                .flatMap(List::stream)
                .distinct()
                .collect(Collectors.toList());
        // Kiểm tra quyền yêu cầu
        if (!permissions.contains(requiredPermission)) {
            throw new AccessDeniedException("User does not have permission: " + requiredPermission);
        }
    }

    public void assignRoleToUser(Integer userId, Integer roleId) {
        String keycloakId = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByKeycloakId(keycloakId);
        checkPermission(user.getId(), "ASSIGN_ROLE_TO_USER");
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
        checkPermission(user.getId(), "REMOVE_ROLE_FROM_USER");
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
