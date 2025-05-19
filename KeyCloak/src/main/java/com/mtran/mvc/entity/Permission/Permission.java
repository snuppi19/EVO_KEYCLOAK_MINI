package com.mtran.mvc.entity.Permission;

import jakarta.persistence.*;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
@Entity
@Table(name = "permission")
public class Permission {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "permission_id")
    private Integer permissionId;
    @Column(name = "resource_code", columnDefinition = "VARCHAR(50)")
    private String resourceCode;

    @Column(name = "scope", columnDefinition = "VARCHAR(50)")
    private String scope;

}
