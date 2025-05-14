package com.mtran.mvc.service.impl;

import com.mtran.mvc.dto.UserDTO;
import com.mtran.mvc.entity.Role.Role;
import com.mtran.mvc.entity.Role.UserRole;
import com.mtran.mvc.entity.User;
import com.mtran.mvc.mapper.UserMapper;
import com.mtran.mvc.repository.RoleRepository;
import com.mtran.mvc.repository.UserRepository;
import com.mtran.mvc.repository.UserRoleRepository;
import com.mtran.mvc.service.UserIamService;
import com.mtran.mvc.support.AppException;
import com.mtran.mvc.support.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class UserIamServiceImpl implements UserIamService {
    private final UserRoleRepository userRoleRepository;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserMapper userMapper;

    @Override
    public UserDTO findByEmail(String email) {
        return userMapper.toUserDTO(userRepository.findByEmail(email));
    }

    @Override
    public void createUser(UserDTO userDTO) {
        if (userRepository.findByEmail(userDTO.getEmail()) != null) {
            throw new RuntimeException("user name existed with : " + userDTO.getEmail());
        }
        User user = userMapper.toUserEntity(userDTO);
        user.setPasswordSynced(false);
        userRepository.save(user);
        UserRole userRole = new UserRole();
        userRole.setUserId(user.getId());
        Role role = roleRepository.findByRoleNameIgnoreCase("USER");
        userRole.setRoleId(role.getRoleId());
        userRoleRepository.save(userRole);
    }

    @Override
    public void updateUser(UserDTO userDTO) {
        User user = userRepository.findByEmail(userDTO.getEmail());
        if (user == null) {
            throw new RuntimeException("user name not existed with : " + userDTO.getEmail());
        }
        user.setName(userDTO.getName());
        user.setPhoneNumber(userDTO.getPhoneNumber());
        if (userDTO.getPassword() != null) {
            user.setPassword(userDTO.getPassword());
        }
        userRepository.save(user);
    }

    @Override
    public void forgotPassword(String email, String password) {
        User user = userRepository.findByEmail(email);
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(15);
        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);
    }

    @Override
    public void changePassword(String email, String oldPassword, String newPassword) {
        User user = userRepository.findByEmail(email);
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(15);
        if (!passwordEncoder.matches(oldPassword, user.getPassword()) && !oldPassword.equals(user.getPassword())) {
            throw new AppException(ErrorCode.PASSWORD_INVALID);
        }
        userRepository.save(user);
    }

    @Override
    public void updateLastChangePassword(String email, LocalDateTime lastChangePassword) {
        User user = userRepository.findByEmail(email);
        user.setLastChangePassword(lastChangePassword);
        userRepository.save(user);
    }

    @Override
    public List<UserDTO> getAllUsers() {
        List<User> users = userRepository.findAll();
        return users.stream().map(userMapper::toUserDTO).toList();
    }
}
