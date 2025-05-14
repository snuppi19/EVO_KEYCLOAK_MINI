package com.mtran.mvc.dto.request;

import lombok.Data;

@Data
public class AssignRoleRequest {
    private Integer userId;
    private Integer roleId;
}