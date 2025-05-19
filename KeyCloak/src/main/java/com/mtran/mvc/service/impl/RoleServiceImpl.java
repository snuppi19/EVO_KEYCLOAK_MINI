package com.mtran.mvc.service.impl;

import com.mtran.mvc.entity.Permission.Permission;
import com.mtran.mvc.entity.Permission.RolePermission;
import com.mtran.mvc.entity.Role.Role;
import com.mtran.mvc.entity.Role.UserRole;
import com.mtran.mvc.repository.PermissionRepository;
import com.mtran.mvc.repository.RolePermissionRepository;
import com.mtran.mvc.repository.RoleRepository;
import com.mtran.mvc.repository.UserRoleRepository;
import com.mtran.mvc.service.RoleService;
import com.mtran.mvc.support.AppException;
import com.mtran.mvc.support.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final UserRoleRepository userRoleRepository;

    public List<Role> findAll() {
        return roleRepository.findAll();
    }
    public Optional<Role> findById(Integer id) {
        return roleRepository.findById(id);
    }
    public Role save(Role role) {
        return roleRepository.save(role);
    }
    @Override
    public ResponseEntity<?> update(Integer id, Role updatedRole) {
        Role role = roleRepository.findById(id).orElse(null);
        if (role != null) {
            role.setRoleName(updatedRole.getRoleName());
        }else{
            throw new AppException(ErrorCode.ROLE_NOT_FOUND);
        }
        roleRepository.save(role);
        return ResponseEntity.ok().build();
    }

    public void deleteById(Integer id) {
        roleRepository.deleteById(id);
    }

    public List<String> getRolesByUserId(int userId) {
        return userRoleRepository.findByUserId(userId)
                .stream()
                .map(userRole -> roleRepository.findById(userRole.getRoleId())
                        .orElseThrow(() -> new RuntimeException("Role not found"))
                        .getRoleName())
                .collect(Collectors.toList());
    }

    // Lấy danh sách quyền của user dựa trên userId
    public List<Permission> getPermissionsByUserId(Integer userId) {
        // Lấy danh sách role_id của user
        List<Integer> roleIds = userRoleRepository.findByUserId(userId)
                .stream()
                .map(UserRole::getRoleId)
                .collect(Collectors.toList());

        // Lấy danh sách permission_id từ bảng role_permission dựa trên danh sách role_id
        List<Integer> permissionIds = rolePermissionRepository.findByRoleIdIn(roleIds)
                .stream()
                .map(RolePermission::getPermissionId)
                .collect(Collectors.toList());

        // Trả về danh sách Permission
        return permissionRepository.findAllById(permissionIds);
    }


    public List<Permission> getPermissionsByRoleName(String roleName) {
        Role role = roleRepository.findByRoleName(roleName)
                .orElseThrow(() -> new RuntimeException("Role not found: " + roleName));
        List<RolePermission> rolePermissions = rolePermissionRepository.findByRoleId(role.getRoleId());
        List<Integer> permissionIds = rolePermissions.stream()
                .map(RolePermission::getPermissionId)
                .collect(Collectors.toList());
        return permissionRepository.findAllById(permissionIds);
    }

    @Override
    public List<Permission> getPermissionsByRoleId(Integer roleId) {
        List<RolePermission> rolePermissions = rolePermissionRepository.findByRoleId(roleId);
        List<Permission> permissionList = rolePermissions.stream()
                //biến rolepermiss thành permission nhờ logic tìm ra perrmission từ permissionId có trong rolepermission
                .map(rolePermission -> permissionRepository.findById(rolePermission.getRolePermissionId()).orElse(null))
                //lọc từ all permission thành những thằng khác null
                .filter(permission -> permission != null)
                .collect(Collectors.toList());
        return permissionList;
    }

    @Override
    public void addPermissionToRole(Integer roleId, Integer permissionId) {
        RolePermission rolePermission = new RolePermission();
        rolePermission.setRoleId(roleId);
        rolePermission.setPermissionId(permissionId);
        rolePermissionRepository.save(rolePermission);
    }

    @Override
    public void removePermissionFromRole(Integer roleId, Integer permissionId) {
        rolePermissionRepository.findByRoleId(roleId).stream()
                // lọc ra những rolepermission có permissionId giống với permissionId truyền vào
                .filter(rp -> rp.getPermissionId().equals(permissionId))
                // lấy ra thằng đầu tiên
                .findFirst()
                //nếu tồn tại thì gọi ra phương thức delete của rolePerrmission để xóa đi
                .ifPresent(rolePermissionRepository::delete);
    }

}
