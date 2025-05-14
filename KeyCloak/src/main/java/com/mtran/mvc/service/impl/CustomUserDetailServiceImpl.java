package com.mtran.mvc.service.impl;

import com.mtran.mvc.dto.CustomUserDetails;
import com.mtran.mvc.entity.User;
import com.mtran.mvc.repository.UserRepository;
import com.mtran.mvc.support.AppException;
import com.mtran.mvc.support.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CustomUserDetailServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;
    private final RoleServiceImpl roleService;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw new AppException(ErrorCode.USER_NOT_FOUND);
        }
        List<String> roles=roleService.getRolesByUserId(user.getId());
        if(roles==null){
            throw new AppException(ErrorCode.USER_NOT_HAVE_ROLES);
        }
        return new CustomUserDetails(user,roles);
    }
}
