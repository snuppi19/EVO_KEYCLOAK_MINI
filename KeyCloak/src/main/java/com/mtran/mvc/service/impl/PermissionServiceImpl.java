package com.mtran.mvc.service.impl;

import com.mtran.mvc.entity.Permission.Permission;
import com.mtran.mvc.repository.PermissionRepository;
import com.mtran.mvc.service.PermissionService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PermissionServiceImpl implements PermissionService {
    private final PermissionRepository permissionRepository;
    public List<Permission> findAll() {
        return permissionRepository.findAll();
    }
    public Optional<Permission> findById(Integer id) {
        return permissionRepository.findById(id);
    }
    public Permission save(Permission permission) {
        return permissionRepository.save(permission);
    }
    public void deleteById(Integer id) {
        permissionRepository.deleteById(id);
    }
}
