package com.mtran.mvc.service.email;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class OtpService {
    @Autowired
    private StringRedisTemplate redisTemplate;

    private static final long EXPIRE_TIME = 3 * 60; // 5 phút
    private static final long RESEND_OTP_TIME= 60; // 1 phút

    public String generateOtp(String email) {
        String otpKey = "otp:" + email;
        String lockKey = "otp_lock:" + email;

        //lock
        if (Boolean.TRUE.equals(redisTemplate.hasKey(lockKey))) {
            throw new RuntimeException("Làm ơn chờ " + RESEND_OTP_TIME + " giây");
        }

        // Tạo OTP
        String otp = String.valueOf((int)((Math.random() * 900000) + 100000)); // random 6 số

        // Lưu OTP và lock
        redisTemplate.opsForValue().set(otpKey, otp, EXPIRE_TIME, TimeUnit.SECONDS);
        redisTemplate.opsForValue().set(lockKey, "lock", RESEND_OTP_TIME, TimeUnit.SECONDS);
        return otp;
    }

    public boolean verifyOtp(String email, String otp) {
        String otpKey = "otp:" + email;
        String savedOtp = redisTemplate.opsForValue().get(otpKey);
        return savedOtp != null && savedOtp.equals(otp);
    }

    public void deleteOtp(String email) {
        redisTemplate.delete("otp:" + email);
        redisTemplate.delete("otp_lock:" + email);
    }
}
