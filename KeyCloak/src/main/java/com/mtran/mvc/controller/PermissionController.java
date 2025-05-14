package com.mtran.mvc.controller;

import com.mtran.mvc.entity.Permission.Permission;
import com.mtran.mvc.service.impl.PermissionServiceImpl;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/permissions")
@Tag(name = "Permission Controller")
public class PermissionController {
    private final PermissionServiceImpl permissionService;

    @Operation( summary = "Lấy danh sách tất cả quyền", description = "API dành cho ADMIN để truy xuất danh sách toàn bộ quyền (permissions)")
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping
    public ResponseEntity<List<Permission>> getAllPermissions() {
        return ResponseEntity.ok(permissionService.findAll());
    }

    @Operation(summary = "Lấy thông tin quyền theo ID",description = "API dành cho ADMIN để lấy thông tin chi tiết của quyền theo ID")
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/{id}")
    public ResponseEntity<Permission> getPermissionById(@PathVariable Integer id) {
        return permissionService.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @Operation(summary = "Tạo mới quyền",description = "API cho phép ADMIN tạo một quyền mới trong hệ thống")
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    public ResponseEntity<Permission> createPermission(@RequestBody Permission permission) {
        return ResponseEntity.ok(permissionService.save(permission));
    }

    @Operation(summary = "Cập nhật thông tin quyền",description = "API cho phép ADMIN cập nhật tên của quyền dựa trên ID")
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{id}")
    public ResponseEntity<Permission> updatePermission(@PathVariable Integer id, @RequestBody Permission permission) {
        return permissionService.findById(id).map(existingPermission -> {
            existingPermission.setPermissionName(permission.getPermissionName());
            return ResponseEntity.ok(permissionService.save(existingPermission));
        }).orElse(ResponseEntity.notFound().build());
    }

    @Operation(summary = "Xóa quyền theo ID",description = "API cho phép ADMIN xóa quyền khỏi hệ thống nếu quyền tồn tại")
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deletePermission(@PathVariable Integer id) {
        if (permissionService.findById(id).isPresent()) {
            permissionService.deleteById(id);
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.notFound().build();
        }
    }
}
