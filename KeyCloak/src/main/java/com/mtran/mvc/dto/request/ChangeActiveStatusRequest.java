package com.mtran.mvc.dto.request;


import com.mtran.mvc.dto.response.UserResponse;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class ChangeActiveStatusRequest {
    private UserResponse user;
    private Boolean isActive;
}
