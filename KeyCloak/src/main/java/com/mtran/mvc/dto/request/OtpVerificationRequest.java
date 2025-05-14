package com.mtran.mvc.dto.request;

import com.mtran.mvc.dto.UserDTO;
import lombok.Data;

@Data
public class OtpVerificationRequest {
    private String email;
    private String otp;
    private UserDTO userDTO;
    private Boolean isRegister;
}