package com.mtran.mvc.dto.request;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Setter
@Getter
public class RefreshRequest_keyCloak {
    private String email;
    private String refreshToken;
}
