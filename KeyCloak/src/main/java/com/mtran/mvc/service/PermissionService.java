package com.mtran.mvc.service;

import com.mtran.mvc.entity.Permission.Permission;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public interface PermissionService {
    List<Permission> findAll();
    Optional<Permission> findById(Integer id);
    Permission save(Permission permission);
    void deleteById(Integer id);
}
