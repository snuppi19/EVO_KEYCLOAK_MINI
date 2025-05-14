package com.mtran.mvc.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.Where;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;


import java.time.LocalDateTime;

@Entity
@Data
@Setter
@Getter
@Table(name = "User_Keyclok")
@SQLDelete(sql = "UPDATE User_Keyclok SET is_deleted = true WHERE id = ?")
@Where(clause = "is_deleted = false")
public class User {
    @Id
    @Column(name = "id", nullable = false)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @Column(name = "keycloakId", nullable = true)
    private String keycloakId;
    @Column(name = "email", nullable = false, columnDefinition = "VARCHAR(100)")
    private String email;
    @Column(name = "password", nullable = false, columnDefinition = "VARCHAR(100)")
    private String password;
    @Column(name = "name", nullable = false, columnDefinition = "VARCHAR(100)")
    private String name;
    @Column(name = "phonenumber", nullable = false, columnDefinition = "VARCHAR(15)")
    private String phoneNumber;
    @Column(name = "last_change_password", nullable = true)
    private LocalDateTime lastChangePassword;
    @Column(name = "password_synced", nullable = false)
    private boolean passwordSynced;
    @Column(name = "is_deleted", nullable = false)
    private boolean isDeleted;
    @Column(name = "is_active", nullable = false)
    private boolean isActive;
    @CreatedBy
    @Column(name = "created_by", updatable = false)
    private String createdBy;
    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdDate;
    @LastModifiedBy
    @Column(name = "updated_by")
    private String updatedBy;
    @LastModifiedDate
    @Column(name = "updated_at")
    private LocalDateTime updatedDate;
}
