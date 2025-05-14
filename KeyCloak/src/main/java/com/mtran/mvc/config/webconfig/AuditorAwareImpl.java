package com.mtran.mvc.config.webconfig;

import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

public class AuditorAwareImpl implements AuditorAware <String>{
    @Override
    public Optional<String> getCurrentAuditor() {
        String email= SecurityContextHolder.getContext().getAuthentication()!=null
                ? SecurityContextHolder.getContext().getAuthentication().getName()
                : "khong xac dinh";
        return Optional.of(email);
    }
}
