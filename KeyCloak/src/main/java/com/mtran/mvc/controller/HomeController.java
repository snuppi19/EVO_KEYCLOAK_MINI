package com.mtran.mvc.controller;

import com.mtran.mvc.dto.response.TokenExchangeResponse;
import com.mtran.mvc.dto.request.*;
import com.mtran.mvc.dto.response.TokenResponse;
import com.mtran.mvc.dto.response.UserResponse;
import com.mtran.mvc.service.impl.UserKeycloakServiceImpl;
import com.mtran.mvc.service.impl.UserActivityLogServiceImpl;
import com.mtran.mvc.service.impl.UserIamServiceImpl;
import com.mtran.mvc.support.ActivityType;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/home")
@Tag(name = "Home Controller")
public class HomeController {
    private final UserKeycloakServiceImpl userKeycloakServiceImpl;
    private final UserIamServiceImpl userService;
    private final com.mtran.mvc.service.email.OtpService OtpService;
    private final UserActivityLogServiceImpl userActivityLogServiceImpl;

    @Operation(summary = "Đăng ký tài khoản", description = "API tạo người dùng mới và gửi OTP xác thực email")
    @PostMapping("/register")
    ResponseEntity<?> register(@RequestBody RegisterRequest registerRequest, HttpServletRequest httpServletRequest) {
        userKeycloakServiceImpl.register(registerRequest);
        userActivityLogServiceImpl.logActivity(registerRequest.getEmail(), ActivityType.REGISTER, "user login",httpServletRequest);
        return ResponseEntity.ok().build();
    }

    @Operation(summary = "Xác thực OTP", description = "API xác minh OTP sau khi đăng ký. Nếu hợp lệ, tài khoản sẽ được tạo")
    @PostMapping("/verify-otp")
    public ResponseEntity<String> verifyOtp(@RequestBody OtpVerificationRequest request, HttpServletRequest httpServletRequest) {
        if (OtpService.verifyOtp(request.getEmail(), request.getOtp()) && request.getIsRegister()) {
            userService.createUser(request.getUserDTO());
            OtpService.deleteOtp(request.getEmail());
            userActivityLogServiceImpl.logActivity(request.getEmail(), ActivityType.VERIFY_OTP, "user verify otp ", httpServletRequest);
            return ResponseEntity.ok("Đăng ký thành công");
        } else {
            return ResponseEntity.badRequest().body("OTP không hợp lệ");
        }
    }

    @Operation(summary = "Đăng nhập",description = "API đăng nhập người dùng. Nếu dùng Keycloak sẽ trả về URL đăng nhập, nếu không thì trả về access token")
    @PostMapping("/login")
    ResponseEntity<?> login(@RequestBody LoginRequest loginRequest, HttpServletRequest httpServletRequest) {
        userKeycloakServiceImpl.login(loginRequest);//xác thực password và tài khoản email
        if (userKeycloakServiceImpl.getLoginUrl() != null) {
            //nếu có login url là đang sử dụng keycloak đẻ đăng nhập
            userActivityLogServiceImpl.logActivity(loginRequest.getEmail(), ActivityType.LOGIN, "user login with Keycloak", httpServletRequest);
            return ResponseEntity.ok(Map.of("message", "Please login via Keycloak", "loginUrl", userKeycloakServiceImpl.getLoginUrl()));
        } else {
            //nếu không dùng keycloak sẽ được trả về cặp token
            TokenResponse tokenResponse = userKeycloakServiceImpl.getTokensAfterLogin(loginRequest.getEmail());
            userActivityLogServiceImpl.logActivity(loginRequest.getEmail(), ActivityType.LOGIN, "user login without Keycloak", httpServletRequest);
            return ResponseEntity.ok(tokenResponse);
        }
    }

    @Operation(summary = "Xử lý callback từ Keycloak",description = "API xử lý mã code từ Keycloak để đổi lấy access token")
    @GetMapping("/callback")
    ResponseEntity<?> handleCallback(@RequestParam("code") String code, HttpServletRequest httpServletRequest) {
        TokenExchangeResponse token = userKeycloakServiceImpl.handleCallback(code);
        return ResponseEntity.ok(token);
    }

    @Operation(summary = "Làm mới access token",description = "API làm mới access token bằng refresh token từ Keycloak" )
    @PostMapping("/refresh-token")
    String refreshToken(@RequestBody RefreshRequest refreshRequestKeyCloak, HttpServletRequest httpServletRequest) {
        TokenExchangeResponse tokenExchangeResponse = userKeycloakServiceImpl.refresh(refreshRequestKeyCloak);
        userActivityLogServiceImpl.logActivity(refreshRequestKeyCloak.getEmail(), ActivityType.REFRESH_TOKEN, "provide new access token ", httpServletRequest);
        return tokenExchangeResponse.getAccessToken();
    }

    @Operation(summary = "Đăng xuất",description = "API đăng xuất người dùng khỏi hệ thống")
    @PostMapping("/logout")
    ResponseEntity<?> logout(@RequestBody LogoutRequest request, HttpServletRequest httpServletRequest) throws Exception {
        userKeycloakServiceImpl.logout(request);
        userActivityLogServiceImpl.logActivity(request.getEmail(), ActivityType.LOGOUT, "User Logout", httpServletRequest);
        return ResponseEntity.ok().build();
    }

    @Operation(summary = "Lấy thông tin người dùng theo ID",description = "API chỉ cho STAFF sử dụng để lấy profile chi tiết của người dùng dựa trên ID")
    @PreAuthorize("hasPermission('user', 'view')")
    @GetMapping("/user-profile/{id}")
    UserResponse getUserProfile(@PathVariable Integer id, HttpServletRequest httpServletRequest) {
        return userKeycloakServiceImpl.getUserProfileById(id);
    }

    @Operation(summary = "Lấy danh sách tất cả người dùng",description = "API phân trang danh sách người dùng, chỉ dành cho STAFF")
    @PreAuthorize("hasPermission('user', 'view')")
    @GetMapping("/all-profiles")
    Page<UserResponse> getAllProfiles(  @RequestParam(defaultValue = "0") int page,
                                        @RequestParam(defaultValue = "10") int size,
                                        @RequestParam(defaultValue = "id") String sortBy,
                                        @RequestParam(defaultValue = "false") boolean descending,
                                        HttpServletRequest httpServletRequest) {
        PagingRequest pagingRequest = new PagingRequest();
        pagingRequest.setPage(page);
        pagingRequest.setSize(size);
        pagingRequest.setSortBy(sortBy);
        pagingRequest.setDescending(descending);
        return userKeycloakServiceImpl.getAllProfiles(pagingRequest);
    }

    @Operation(summary = "Đặt lại mật khẩu",description = "API cho phép người dùng đổi mật khẩu. Yêu cầu vai trò USER")
    @PreAuthorize("hasPermission('user', 'update')")
    @PutMapping("/reset-password")
    ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest changePasswordRequest, HttpServletRequest httpServletRequest) {
        userActivityLogServiceImpl.logActivity(changePasswordRequest.getUser().getEmail(), ActivityType.RESET_PASSWORD, "User reset password", httpServletRequest);
        return userKeycloakServiceImpl.changePassword(changePasswordRequest);
    }

    @Operation(summary = "Xóa mềm người dùng",description = "API chỉ cho ADMIN sử dụng để đánh dấu xóa tài khoản người dùng")
    @PreAuthorize("hasPermission('user', 'delete')")
    @PutMapping("/soft-delete")
    ResponseEntity<?> softDelete(@RequestBody DeleteRequest deleteRequest, HttpServletRequest httpServletRequest) {
        userActivityLogServiceImpl.logActivity(deleteRequest.getUser().getEmail(), ActivityType.DELETE_ACCOUNT, "Delete account", httpServletRequest);
        return userKeycloakServiceImpl.softDelete(deleteRequest);
    }

    @Operation(summary = "Thay đổi trạng thái hoạt động của người dùng",description = "API cho phép STAFF khóa hoặc mở khóa tài khoản người dùng")
    @PreAuthorize("hasPermission('user', 'update')")
    @PutMapping("/change-active-status")
    ResponseEntity<?> changeActiveStatus(@RequestBody ChangeActiveStatusRequest changeActiveStatusRequest, HttpServletRequest httpServletRequest) {
        boolean checkStatus = changeActiveStatusRequest.getIsActive();
        if (checkStatus) {
            userActivityLogServiceImpl.logActivity(changeActiveStatusRequest.getUser().getEmail(), ActivityType.UNLOCK_USER, "Change active status to ACTIVE", httpServletRequest);
        } else {
            userActivityLogServiceImpl.logActivity(changeActiveStatusRequest.getUser().getEmail(), ActivityType.BLOCK_USER, "Change active status to INACTIVE", httpServletRequest);
        }
        return userKeycloakServiceImpl.changeActiveStatus(changeActiveStatusRequest);
    }

    @Operation(summary = "Gán vai trò cho người dùng",description = "API cho ADMIN sử dụng để gán role cho người dùng")
    @PreAuthorize("hasPermission('role', 'create')")
    @PostMapping("/assign-role")
    ResponseEntity<?> assignRole(@RequestBody AssignRoleRequest assignRoleRequest, HttpServletRequest httpServletRequest) {
        userKeycloakServiceImpl.assignRoleToUser(assignRoleRequest.getUserId(), assignRoleRequest.getRoleId());
        userActivityLogServiceImpl.logActivity(
                SecurityContextHolder.getContext().getAuthentication().getName(),
                ActivityType.ASSIGN_ROLE,
                "Assigned role " + assignRoleRequest.getRoleId() + " to user " + assignRoleRequest.getUserId(),
                httpServletRequest
        );
        return ResponseEntity.ok().build();
    }

    @Operation(summary = "Gỡ vai trò khỏi người dùng",description = "API cho ADMIN sử dụng để gỡ role khỏi người dùng")
    @PreAuthorize("hasPermission('role', 'delete')")
    @DeleteMapping("/remove-role")
    ResponseEntity<?> removeRole(@RequestBody AssignRoleRequest assignRoleRequest, HttpServletRequest httpServletRequest) {
        userKeycloakServiceImpl.removeRoleFromUser(assignRoleRequest.getUserId(), assignRoleRequest.getRoleId());
        userActivityLogServiceImpl.logActivity(
                SecurityContextHolder.getContext().getAuthentication().getName(),
                ActivityType.REMOVE_ROLE,
                "Remove role " + assignRoleRequest.getRoleId() + " From user " + assignRoleRequest.getUserId(),
                httpServletRequest
        );
        return ResponseEntity.ok().build();
    }
}
