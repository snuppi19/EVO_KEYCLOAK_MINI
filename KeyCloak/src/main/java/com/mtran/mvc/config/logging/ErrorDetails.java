package com.mtran.mvc.config.logging;

import java.time.LocalDateTime;

//CLASS NÀY ĐỂ BẮT LỖI VÀ THỜI GIAN XẢY RA
public class ErrorDetails {
    private LocalDateTime timestamp;
    private String message;

    public ErrorDetails(LocalDateTime timestamp, String message) {
        this.timestamp = timestamp;
        this.message = message;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }
    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
    public String getMessage() {
        return message;
    }
    public void setMessage(String message) {
        this.message = message;
    }
}