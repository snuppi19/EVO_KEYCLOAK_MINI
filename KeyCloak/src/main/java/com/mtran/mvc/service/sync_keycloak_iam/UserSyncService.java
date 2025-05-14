package com.mtran.mvc.service.sync_keycloak_iam;

import com.mtran.mvc.dto.identity.Credential;
import com.mtran.mvc.dto.request.TokenExchangeParamRequest;
import com.mtran.mvc.dto.response.TokenExchangeResponse;
import com.mtran.mvc.dto.request.UserCreateParamRequest;
import com.mtran.mvc.entity.KeycloakProperties;
import com.mtran.mvc.entity.User;
import com.mtran.mvc.repository.IdentityClient;
import com.mtran.mvc.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Data
@RequiredArgsConstructor
public class UserSyncService {
    private final UserRepository userRepository;
    private final IdentityClient identityClient;
    private final KeycloakProperties keycloakProperties;

    @PostConstruct
    public void syncUsers() {
        //tự động kiểm tra và tạo ngươif dùng trên keycloak dựa vào database
        if (keycloakProperties.isEnabled()) {
            List<User> users = userRepository.findAll();
            TokenExchangeResponse adminToken = identityClient.exchangeToken(TokenExchangeParamRequest.builder()
                    .grant_type("client_credentials")
                    .scope("openid")
                    .client_id(keycloakProperties.getClientId())
                    .client_secret(keycloakProperties.getClientSecret())
                    .build());

            for (User user : users) {
                //nếu chưa có keycloak id
                if (user.getKeycloakId() == null) {
                    String keycloakId = extractUserId(identityClient.createUser("Bearer " + adminToken.getAccessToken(),
                            UserCreateParamRequest.builder()
                                    .firstName(user.getName())
                                    .email(user.getEmail())
                                    .enabled(true)
                                    .emailVerified(false)
                                    .credentials(List.of(Credential.builder()
                                            .type("password")
                                            .temporary(false)
                                            .value(user.getPassword())
                                            .build()))
                                    .build()));
                    user.setKeycloakId(keycloakId);
                    //BCRYPT
                    PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(15);
                    user.setPassword(passwordEncoder.encode(user.getPassword()));
                    userRepository.save(user);
                }

                if (!user.isPasswordSynced()) {
                    identityClient.resetPassword(
                            "Bearer " + adminToken.getAccessToken(),
                            keycloakProperties.getRealm(),
                            user.getKeycloakId(),
                            Credential.builder()
                                    .type("password")
                                    .temporary(false)
                                    .value(user.getPassword())
                                    .build()
                    );
                    user.setPasswordSynced(true);
                    userRepository.save(user);
                }
            }
        }
    }

    private String extractUserId(ResponseEntity<?> response) {
        String location = response.getHeaders().get("Location").get(0);
        String[] split = location.split("/");
        return split[split.length - 1];
    }
}