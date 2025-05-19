package com.mtran.mvc.service.role_permission_default;

import com.mtran.mvc.entity.Permission.Permission;
import com.mtran.mvc.entity.Permission.RolePermission;
import com.mtran.mvc.entity.Role.Role;
import com.mtran.mvc.repository.PermissionRepository;
import com.mtran.mvc.repository.RolePermissionRepository;
import com.mtran.mvc.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;

import java.util.Optional;

@Component
@RequiredArgsConstructor
public class DefaultRolePermission {
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final RolePermissionRepository rolePermissionRepository;

    @PostConstruct
    public void init() {
        // Tạo quyền cho resource = 'user'
        createPermissionIfNotExists("user", "create");
        createPermissionIfNotExists("user", "update");
        createPermissionIfNotExists("user", "view");
        createPermissionIfNotExists("user", "delete");

        // Tạo quyền cho resource = 'role'
        createPermissionIfNotExists("role", "create");
        createPermissionIfNotExists("role", "update");
        createPermissionIfNotExists("role", "view");
        createPermissionIfNotExists("role", "delete");

        // Tạo quyền cho resource = 'permission'
        createPermissionIfNotExists("permission", "create");
        createPermissionIfNotExists("permission", "update");
        createPermissionIfNotExists("permission", "view");
        createPermissionIfNotExists("permission", "delete");

        // Tạo vai trò
        Role userManager = createRoleIfNotExists("USER");
        Role systemAdmin = createRoleIfNotExists("ADMIN");
        Role staff = createRoleIfNotExists("STAFF");

        // Gán quyền cho vai trò USER
        assignPermissionToRole(userManager.getRoleId(), "user", "view");
        assignPermissionToRole(userManager.getRoleId(), "user", "update");

        // Gán quyền cho vai trò ADMIN
        assignPermissionToRole(systemAdmin.getRoleId(), "user", "create");
        assignPermissionToRole(systemAdmin.getRoleId(), "user", "update");
        assignPermissionToRole(systemAdmin.getRoleId(), "user", "view");
        assignPermissionToRole(systemAdmin.getRoleId(), "user", "delete");
        assignPermissionToRole(systemAdmin.getRoleId(), "role", "create");
        assignPermissionToRole(systemAdmin.getRoleId(), "role", "update");
        assignPermissionToRole(systemAdmin.getRoleId(), "role", "view");
        assignPermissionToRole(systemAdmin.getRoleId(), "role", "delete");
        assignPermissionToRole(systemAdmin.getRoleId(), "permission", "create");
        assignPermissionToRole(systemAdmin.getRoleId(), "permission", "update");
        assignPermissionToRole(systemAdmin.getRoleId(), "permission", "view");
        assignPermissionToRole(systemAdmin.getRoleId(), "permission", "delete");

        // Gán quyền cho vai trò STAFF
        assignPermissionToRole(staff.getRoleId(), "user", "view");
        assignPermissionToRole(staff.getRoleId(), "user", "update");
        assignPermissionToRole(staff.getRoleId(), "user", "delete");
    }

    private void createPermissionIfNotExists(String resourceCode, String scope) {
        Permission permission = permissionRepository.findByResourceCodeAndScope(resourceCode, scope);
        if (permission == null) {
            Permission permissionNew = new Permission();
            permissionNew.setResourceCode(resourceCode);
            permissionNew.setScope(scope);
            permissionRepository.save(permissionNew);
        }
    }

    private Role createRoleIfNotExists(String roleName) {
        Optional<Role> existingRole = roleRepository.findByRoleName(roleName);
        if (existingRole.isPresent()) {
            return existingRole.get();
        }
        Role role = new Role();
        role.setRoleName(roleName);
        return roleRepository.save(role);
    }

    private void assignPermissionToRole(Integer roleId, String resourceCode, String scope) {
        Permission permission = permissionRepository.findByResourceCodeAndScope(resourceCode, scope);
        if (permission == null) {
            throw new RuntimeException("Permission not found for resource: " + resourceCode + ", scope: " + scope);
        }
        if (!rolePermissionRepository.existsByRoleIdAndPermissionId(roleId, permission.getPermissionId())) {
            RolePermission rp = new RolePermission();
            rp.setRoleId(roleId);
            rp.setPermissionId(permission.getPermissionId());
            rolePermissionRepository.save(rp);
        }
    }
}