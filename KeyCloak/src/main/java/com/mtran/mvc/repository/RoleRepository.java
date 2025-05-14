package com.mtran.mvc.repository;

import com.mtran.mvc.entity.Role.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByRoleName(String roleName);
    Role findByRoleNameIgnoreCase(String roleName);
}
