package com.mtran.mvc.repository;


import com.mtran.mvc.dto.response.UserResponse;
import com.mtran.mvc.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository  extends JpaRepository<User, String> {
    User findByEmail(String email);
    User findById(int id);
    User findByKeycloakId(String keycloakId);
    Page<User> findAll(Pageable pageable);

}
