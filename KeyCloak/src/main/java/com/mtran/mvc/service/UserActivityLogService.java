package com.mtran.mvc.service;

import com.mtran.mvc.support.ActivityType;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

@Service
public interface UserActivityLogService {
    void logActivity(String email, ActivityType activityType, String description, HttpServletRequest request);
}
