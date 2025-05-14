package com.mtran.mvc.service.impl;


import com.mtran.mvc.entity.UserActivityLog;
import com.mtran.mvc.repository.UserActivityLogRepository;
import com.mtran.mvc.service.UserActivityLogService;
import com.mtran.mvc.support.ActivityType;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserActivityLogServiceImpl implements UserActivityLogService {
    private final UserActivityLogRepository userActivityLogRepository;

    private String getClientIpAddress(HttpServletRequest request) {
        String ipAddress = request.getHeader("X-Forwarded-For");
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getRemoteAddr();
        }
        return ipAddress;
    }

    public void logActivity(String email, ActivityType activityType, String description, HttpServletRequest request) {
        String ipAddress = getClientIpAddress(request);
        UserActivityLog log = new UserActivityLog(email, activityType.name(), description, ipAddress);
        userActivityLogRepository.save(log);
    }

}
