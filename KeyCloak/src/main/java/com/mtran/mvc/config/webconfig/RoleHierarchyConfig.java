package com.mtran.mvc.config.webconfig;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;


//CLASS NÀY KHAI BÁO PHÂN CẤP CÁC QUYỀN HẠN
@Configuration
public class RoleHierarchyConfig {

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        //ADMIN BAO GỒM CÁC QUYỀN MÀ STAFF VÀ USER CÓ ,..
        roleHierarchy.setHierarchy("""
            ROLE_ADMIN > ROLE_STAFF
            ROLE_STAFF > ROLE_USER
        """);
        return roleHierarchy;
    }
}