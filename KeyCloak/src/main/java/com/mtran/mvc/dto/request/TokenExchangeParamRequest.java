package com.mtran.mvc.dto.request;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class TokenExchangeParamRequest {
    String refresh_token;
    String grant_type;
    String client_id;
    String code;
    String redirect_uri;
    String client_secret;
    String scope;
}