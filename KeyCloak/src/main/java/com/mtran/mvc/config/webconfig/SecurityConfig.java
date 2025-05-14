package com.mtran.mvc.config.webconfig;

import com.mtran.mvc.config.utils.jwt.JwtAuthenticationFilter;
import com.mtran.mvc.entity.KeycloakProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final KeycloakProperties keycloakProperties;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomJwtAuthenticationConverter customJwtAuthenticationConverter;
    private final String[] PUBLIC_ENDPOINTS = {"/home/register", "/home/login", "/home/callback", "/home/logout"
            , "/home/verify-otp", "/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**","/v3/api-docs.yaml"};

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(request -> request
                .requestMatchers(PUBLIC_ENDPOINTS)
                .permitAll()
                .anyRequest()
                .authenticated());


        httpSecurity.csrf(AbstractHttpConfigurer::disable);
        // NẾU THUỘC TÍNH KEYCLOAK ENABLE XÁC ĐỊNH SỬ DỤNG OATH2 RESOURCE SERVER HOẶC JWTAUTHENTICATION FILTER

        if (keycloakProperties.isEnabled()) {
            httpSecurity.oauth2ResourceServer(oauth2 -> oauth2
                    .jwt(jwtConfigurer -> jwtConfigurer
                            .jwkSetUri(keycloakProperties.getAuthServerUrl() + "/realms/" +
                                    keycloakProperties.getRealm() + "/protocol/openid-connect/certs")
                            //SỬ DỤNG CUSTOM XÁC THỰC: LẤY THÔNG TIN CHỌC VÀO DATABSE - XÁC ĐỊNH QUYỀN
                            .jwtAuthenticationConverter(jwtAuthenticationConverter())
                    ));
        } else {
            httpSecurity.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        }
        return httpSecurity.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(customJwtAuthenticationConverter);
        return jwtAuthenticationConverter;
    }
}