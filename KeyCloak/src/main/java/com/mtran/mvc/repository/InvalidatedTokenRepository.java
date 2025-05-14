package com.mtran.mvc.repository;

import com.mtran.mvc.entity.InvalidateToken;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface InvalidatedTokenRepository extends JpaRepository<InvalidateToken,String> {
    @Modifying
    @Transactional
    @Query("DELETE FROM InvalidateToken")
    void deleteByExpiryTimeBefore();
}
