package com.mtran.mvc.config.cronjob;

import com.mtran.mvc.repository.InvalidatedTokenRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Date;

//CLASS NÀY ĐỂ LẬP LỊCH TỰ ĐỘNG XÓA INVALIDATE TOKEN ( TỪ IAM 1 )
@Component
public class TokenCleanupJob {
    private static final int EXPIRY_TIME_IN_SECONDS_CRONJOB = 86400000;// 1 ngày
    private final InvalidatedTokenRepository invalidatedTokenRepository;

    public TokenCleanupJob(InvalidatedTokenRepository invalidatedTokenRepository) {
        this.invalidatedTokenRepository = invalidatedTokenRepository;
    }

    @Scheduled(fixedRate = EXPIRY_TIME_IN_SECONDS_CRONJOB)
    public void cleanUpExpiredToken(){
        Date date=new Date();
        invalidatedTokenRepository.deleteByExpiryTimeBefore();
        System.out.println("Cleaned up expired invalidated tokens at: " + date);
    }
}
