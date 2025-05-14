package com.mtran.mvc.repository;

import com.mtran.mvc.dto.identity.*;
import com.mtran.mvc.dto.request.TokenExchangeParamRequest;
import com.mtran.mvc.dto.request.UserCreateParamRequest;
import com.mtran.mvc.dto.request.UserUpdateParamRequest;
import com.mtran.mvc.dto.response.TokenExchangeResponse;
import com.mtran.mvc.dto.response.UserResponse;
import com.mtran.mvc.entity.Role.Role;
import feign.QueryMap;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
//Class xác định api của Keycloak
@FeignClient(name = "identity-service", url = "http://localhost:8081")
public interface IdentityClient {
    // tạo ra token
    @PostMapping(value = "/realms/dev/protocol/openid-connect/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    TokenExchangeResponse exchangeToken(@QueryMap TokenExchangeParamRequest param);

    //tạo user tren keycloak
    @PostMapping(value = "/admin/realms/dev/users",
            consumes = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<?> createUser(
            @RequestHeader("Authorization") String authorization,
            @RequestBody UserCreateParamRequest param);

    // logout trên keycloak
    @PostMapping(value = "/realms/dev/protocol/openid-connect/logout",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    void logout(@RequestHeader("Authorization") String authorization, @QueryMap TokenExchangeParamRequest param);

    //lay thong tin nguoi dung tren keycloak
    @GetMapping(value = "/admin/realms/dev/users/{id}")
    UserResponse getUser(
            @RequestHeader("Authorization") String authorization,
            @PathVariable("id") String id);

    @GetMapping("/admin/realms/{realm}/users/{userId}/sessions")
    void revokeUserSessions(@RequestHeader("Authorization") String authorization,
                            @PathVariable("realm") String realm,
                            @PathVariable("userId") String userId);

    //thay đổi mật khẩu của user trên keycloak
    @PutMapping(value = "/admin/realms/{realm}/users/{userId}/reset-password",
            consumes = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<?> resetPassword(
            @RequestHeader("Authorization") String authorization,
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId,
            @RequestBody Credential credential);

    // thay dổi trạng thái của user trên keycloak
    @PutMapping(value = "/admin/realms/{realm}/users/{userId}",
            consumes = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<?> ChangeStatusUser(
            @RequestHeader("Authorization") String authorization,
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId,
            @RequestBody UserUpdateParamRequest param);

    @GetMapping("/admin/realms/{realm}/roles")
    List<Role> getRealmRoles(
            @RequestHeader("Authorization") String authorization,
            @PathVariable("realm") String realm
    );

    @GetMapping("/admin/realms/{realm}/clients/{clientId}/roles")
    List<Role> getClientRoles(
            @RequestHeader("Authorization") String authorization,
            @PathVariable("realm") String realm,
            @PathVariable("clientId") String clientId
    );

    @PostMapping("/admin/realms/{realm}/users/{id}/role-mappings/realm")
    void addRealmRolesToUser(
            @RequestHeader("Authorization") String authorization,
            @PathVariable("realm") String realm,
            @PathVariable("id") String userId,
            @RequestBody List<Role> roles
    );

    @PostMapping("/admin/realms/{realm}/users/{id}/role-mappings/clients/{clientId}")
    void addClientRolesToUser(
            @RequestHeader("Authorization") String authorization,
            @PathVariable("realm") String realm,
            @PathVariable("id") String userId,
            @PathVariable("clientId") String clientId,
            @RequestBody List<Role> roles
    );
}
