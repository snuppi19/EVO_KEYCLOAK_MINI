package com.mtran.mvc.mapper;

import com.mtran.mvc.dto.request.RegisterRequest;
import com.mtran.mvc.dto.response.UserResponse;
import com.mtran.mvc.entity.User;
import org.mapstruct.Mapper;
//Class này dùng cho keycloak
@Mapper(componentModel = "spring")
public interface UserMapperKeycloak {
    UserResponse toUserResponse(User user);
    User toUser(RegisterRequest registerRequest);

    User toUserEntity(UserResponse userResponse);
    RegisterRequest toUserRequest(User user);



}