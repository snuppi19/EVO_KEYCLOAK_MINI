package com.mtran.mvc.repository;

import com.mtran.mvc.entity.Permission.RolePermission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RolePermissionRepository extends JpaRepository<RolePermission, Integer> {
    List<RolePermission> findByRoleId(Integer roleId);
    List<RolePermission> findByRoleIdIn(List<Integer> roleIds);
    @Query("SELECT rp.permissionId FROM RolePermission rp WHERE rp.roleId = :roleId")
    List<Integer> findPermissionIdsByRoleId(Integer roleId);
    boolean existsByRoleIdAndPermissionId(Integer roleId, Integer permissionId);
}
