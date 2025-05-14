package com.mtran.mvc.config.webconfig;

import com.mtran.mvc.entity.Role.Role;
import com.mtran.mvc.entity.Role.UserRole;
import com.mtran.mvc.entity.User;
import com.mtran.mvc.repository.RoleRepository;
import com.mtran.mvc.repository.UserRepository;
import com.mtran.mvc.repository.UserRoleRepository;
import com.mtran.mvc.service.impl.RoleServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
//CLASS NÀY CUSTOME XÁC THỰC BẰNG CÁCH XÁC ĐỊNH QUYỀN BẰNG DATABASE
public class CustomJwtAuthenticationConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    private final UserRepository userRepository;
    private final RoleServiceImpl roleService;
    private final RoleHierarchy roleHierarchy;
    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        String keycloakId = jwt.getSubject();
        String email = jwt.getClaimAsString("email");
        String identityProvider = jwt.getClaimAsString("identity_provider");
        String givenName = jwt.getClaimAsString("given_name");

        if (email == null || email.isEmpty()) {
            return Collections.emptyList();
        }

        User user = userRepository.findByEmail(email);
        // TÍCH HỢP GOOGLE SSO
        if (user == null) {
            // NẾU ĐĂNG NHẬP BẰNG GOOGLE THÌ MỚI CHO TẠO MỚI USER
            if ("google".equals(identityProvider)) {
                user = new User();
                user.setKeycloakId(keycloakId);
                user.setEmail(email != null ? email : keycloakId + "@sso.example.com");
                user.setName(givenName != null ? givenName : "");
                user.setPassword("SSO_" + keycloakId);
                user.setPhoneNumber("N/A");
                user.setPasswordSynced(false);
                user.setActive(true);
                user.setDeleted(false);
                user.setCreatedBy("SYSTEM");
                user.setCreatedDate(LocalDateTime.now());
                try {
                    user = userRepository.save(user);
                    UserRole userRole = new UserRole();
                    userRole.setUserId(user.getId());
                    Role role = roleRepository.findByRoleNameIgnoreCase("USER");
                    userRole.setRoleId(role.getRoleId());
                    userRoleRepository.save(userRole);
                } catch (Exception e) {
                    return Collections.emptyList();
                }
            } else {
                return Collections.emptyList();
            }
        }

        List<String> roles = roleService.getRolesByUserId(user.getId());
        if (roles == null || roles.isEmpty()) {
            return Collections.emptyList();
        }

        // Chuyển đổi roles thành GrantedAuthority
        List<GrantedAuthority> authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());

        // Áp dụng RoleHierarchy để mở rộng quyền
        Collection<? extends GrantedAuthority> reachableAuthorities =
                roleHierarchy.getReachableGrantedAuthorities(authorities);

        // Chuyển đổi reachableAuthorities thành List<GrantedAuthority>
        List<GrantedAuthority> finalAuthorities = reachableAuthorities.stream()
                .map(auth -> (GrantedAuthority) auth)
                .collect(Collectors.toList());

        return finalAuthorities;
    }
}

