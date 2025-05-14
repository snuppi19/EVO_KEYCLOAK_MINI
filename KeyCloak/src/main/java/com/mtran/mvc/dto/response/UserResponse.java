package com.mtran.mvc.dto.response;

import lombok.*;

@Data
@Setter
@Getter
public class UserResponse {
    private String Id;
    private String keycloakId;
    private String email;
    private String password;
    private String name;
    private String phoneNumber;
}
