package com.mtran.mvc.config.webconfig;

import com.mtran.mvc.entity.Permission.Permission;
import com.mtran.mvc.entity.Permission.RolePermission;
import com.mtran.mvc.entity.User;
import com.mtran.mvc.repository.PermissionRepository;
import com.mtran.mvc.repository.RolePermissionRepository;
import com.mtran.mvc.repository.UserRepository;
import com.mtran.mvc.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class CustomPermissionEvaluator implements PermissionEvaluator {
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final PermissionRepository permissionRepository;

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        String resource = (String) targetDomainObject;
        String scope = (String) permission;

        // Lấy user từ authentication
        String keycloakId = authentication.getName();
        User user = userRepository.findByKeycloakId(keycloakId);
        if (user == null) {
            return false;
        }

        // Lấy danh sách role_id của user
        List<Integer> roleIds = userRoleRepository.findRoleIdsByUserId(user.getId());
        if (roleIds.isEmpty()) {
            return false;
        }

        // Lấy danh sách permission_id từ role_id qua bảng role_permission
        List<Integer> permissionIds = roleIds.stream()
                // biến tất cả permisson id của từng role sở hữu thành 1 mảng duy nhất
                .flatMap(roleId -> rolePermissionRepository.findPermissionIdsByRoleId(roleId).stream())
                .distinct()
                .collect(Collectors.toList());

        // Lấy danh sách Permission từ permission_id
        List<Permission> permissions = permissionRepository.findAllById(permissionIds);

        // Kiểm tra xem user có quyền tương ứng với resource và scope không
        return permissions.stream()
                .anyMatch(p -> p.getResourceCode().equals(resource) && p.getScope().equals(scope));
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        String resource = targetType;
        String scope = (String) permission;

        // Lấy user từ authentication
        String keycloakId = authentication.getName();
        User user = userRepository.findByKeycloakId(keycloakId);
        if (user == null) {
            return false;
        }

        // Lấy danh sách role_id của user
        List<Integer> roleIds = userRoleRepository.findRoleIdsByUserId(user.getId());
        if (roleIds.isEmpty()) {
            return false;
        }

        // Lấy danh sách permission_id từ role_id qua bảng role_permission
        List<Integer> permissionIds = roleIds.stream()
                .flatMap(roleId -> rolePermissionRepository.findPermissionIdsByRoleId(roleId).stream())
                .distinct()
                .collect(Collectors.toList());

        // Lấy danh sách Permission từ permission_id
        List<Permission> permissions = permissionRepository.findAllById(permissionIds);

        // Kiểm tra xem user có quyền tương ứng với resource và scope không
        return permissions.stream()
                .anyMatch(p -> p.getResourceCode().equals(resource) && p.getScope().equals(scope));
    }
}