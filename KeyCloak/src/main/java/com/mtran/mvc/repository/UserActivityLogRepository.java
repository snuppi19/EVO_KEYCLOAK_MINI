package com.mtran.mvc.repository;

import com.mtran.mvc.entity.UserActivityLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserActivityLogRepository extends JpaRepository<UserActivityLog,Long> {
   List<UserActivityLog> findByEmail(String email);
}
