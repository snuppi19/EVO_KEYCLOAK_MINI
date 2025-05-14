package com.mtran.mvc.entity;


import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@ConfigurationProperties(prefix = "keycloak")
@Configuration
public class KeycloakProperties {
    private boolean enabled;
    private String realm;
    private String authServerUrl;
    private String clientId;
    private String clientSecret;
    private String redirectUri;
}
