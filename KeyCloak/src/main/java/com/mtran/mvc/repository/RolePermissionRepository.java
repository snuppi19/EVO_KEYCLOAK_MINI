package com.mtran.mvc.repository;

import com.mtran.mvc.entity.Permission.RolePermission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RolePermissionRepository extends JpaRepository<RolePermission, Integer> {
    List<RolePermission> findByRoleId(Integer roleId);
    List<RolePermission> findByRoleIdIn(List<Integer> roleIds);

    boolean existsByRoleIdAndPermissionId(Integer roleId, Integer permissionId);
}
