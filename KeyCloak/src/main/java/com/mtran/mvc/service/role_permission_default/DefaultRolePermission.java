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
//class tạo sẵn quyền và role
public class DefaultRolePermission {
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final RolePermissionRepository rolePermissionRepository;

    @PostConstruct
    public void init() {
        // Tạo quyền
        createPermissionIfNotExists("VIEW_USER_PROFILE");
        createPermissionIfNotExists("VIEW_ALL_USERS_PROFILE");
        createPermissionIfNotExists("RESET_PASSWORD");
        createPermissionIfNotExists("SOFT_DELETE_USER");
        createPermissionIfNotExists("CHANGE_USER_STATUS");
        createPermissionIfNotExists("VIEW_PERMISSION");
        createPermissionIfNotExists("CREATE_PERMISSION");
        createPermissionIfNotExists("UPDATE_PERMISSION");
        createPermissionIfNotExists("DELETE_PERMISSION");
        createPermissionIfNotExists("VIEW_ROLE");
        createPermissionIfNotExists("CREATE_ROLE");
        createPermissionIfNotExists("UPDATE_ROLE");
        createPermissionIfNotExists("DELETE_ROLE");
        createPermissionIfNotExists("VIEW_ROLE_PERMISSION");
        createPermissionIfNotExists("ASSIGN_PERMISSION_TO_ROLE");
        createPermissionIfNotExists("REMOVE_PERMISSION_FROM_ROLE");
        createPermissionIfNotExists("ASSIGN_ROLE_TO_USER");
        createPermissionIfNotExists("REMOVE_ROLE_FROM_USER");

        // Tạo vai trò
        Role userManager = createRoleIfNotExists("USER");
        Role systemAdmin = createRoleIfNotExists("ADMIN");
        Role staff = createRoleIfNotExists("STAFF");

        // Gán quyền cho vai trò USER
        assignPermissionToRole(userManager.getRoleId(), "VIEW_USER_PROFILE");
        assignPermissionToRole(userManager.getRoleId(), "RESET_PASSWORD");

        // Gán quyền cho vai trò ADMIN
        assignPermissionToRole(systemAdmin.getRoleId(), "VIEW_PERMISSION");
        assignPermissionToRole(systemAdmin.getRoleId(), "CREATE_PERMISSION");
        assignPermissionToRole(systemAdmin.getRoleId(), "UPDATE_PERMISSION");
        assignPermissionToRole(systemAdmin.getRoleId(), "DELETE_PERMISSION");
        assignPermissionToRole(systemAdmin.getRoleId(), "VIEW_ROLE");
        assignPermissionToRole(systemAdmin.getRoleId(), "CREATE_ROLE");
        assignPermissionToRole(systemAdmin.getRoleId(), "UPDATE_ROLE");
        assignPermissionToRole(systemAdmin.getRoleId(), "DELETE_ROLE");
        assignPermissionToRole(systemAdmin.getRoleId(), "VIEW_ROLE_PERMISSION");
        assignPermissionToRole(systemAdmin.getRoleId(), "ASSIGN_PERMISSION_TO_ROLE");
        assignPermissionToRole(systemAdmin.getRoleId(), "REMOVE_PERMISSION_FROM_ROLE");
        assignPermissionToRole(systemAdmin.getRoleId(), "ASSIGN_ROLE_TO_USER");
        assignPermissionToRole(systemAdmin.getRoleId(), "REMOVE_ROLE_FROM_USER");

        //Gán quyền cho vai trò STAFF
        assignPermissionToRole(staff.getRoleId(), "VIEW_USER_PROFILE");
        assignPermissionToRole(staff.getRoleId(), "VIEW_ALL_USERS_PROFILE");
        assignPermissionToRole(staff.getRoleId(), "RESET_PASSWORD");
        assignPermissionToRole(staff.getRoleId(), "SOFT_DELETE_USER");
        assignPermissionToRole(staff.getRoleId(), "CHANGE_USER_STATUS");
    }

    private void createPermissionIfNotExists(String permissionName) {
        Permission permission = permissionRepository.findByPermissionName(permissionName);
        if (permission == null) {
            Permission permissionNew = new Permission();
            permissionNew.setPermissionName(permissionName);
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

    private void assignPermissionToRole(Integer roleId, String permissionName) {
        Permission permission = permissionRepository.findByPermissionName(permissionName);
        if (!rolePermissionRepository.existsByRoleIdAndPermissionId(roleId, permission.getPermissionId())) {
            RolePermission rp = new RolePermission();
            rp.setRoleId(roleId);
            rp.setPermissionId(permission.getPermissionId());
            rolePermissionRepository.save(rp);
        }
    }
}