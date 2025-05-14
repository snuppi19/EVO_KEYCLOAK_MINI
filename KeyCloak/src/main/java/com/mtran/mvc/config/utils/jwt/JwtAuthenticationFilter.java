package com.mtran.mvc.config.utils.jwt;

import com.mtran.mvc.entity.KeycloakProperties;
import com.mtran.mvc.service.impl.CustomUserDetailServiceImpl;
import com.mtran.mvc.service.impl.UserIamServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@AllArgsConstructor
@Getter
@Setter
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;
    private final UserIamServiceImpl userService;
    private final CustomUserDetailServiceImpl userDetailService;
    private final KeycloakProperties keycloakProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (keycloakProperties.isEnabled()) {
            filterChain.doFilter(request, response);
            return;
        }

        //lay email tu jwt token
        final String authHeader = request.getHeader("Authorization");
        String jwt = null;
        String email = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7);
            try {
                email = jwtUtil.extractEmail(jwt);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        //spring xac thuc nguoi dung
        if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails=userDetailService.loadUserByUsername(email);
            try {
                if (jwtUtil.validateToken(jwt) != null) {
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails, null, userDetails.getAuthorities()
                            );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        filterChain.doFilter(request, response);
    }
}
