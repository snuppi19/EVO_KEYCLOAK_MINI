package com.mtran.mvc.service;

import com.mtran.mvc.entity.Permission.Permission;
import com.mtran.mvc.entity.Role.Role;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public interface RoleService {
    List<Role> findAll();
    Optional<Role> findById(Integer id);
    Role save(Role role);
    ResponseEntity<?> update(Integer id, Role updatedRole);
    void deleteById(Integer id);
    List<Permission> getPermissionsByRoleId(Integer roleId);
    void addPermissionToRole(Integer roleId, Integer permissionId);
    void removePermissionFromRole(Integer roleId, Integer permissionId);
}
