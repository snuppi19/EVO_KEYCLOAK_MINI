package com.mtran.mvc.config.logging;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;


//CLASS NÀY DÙNG ĐỂ LOGGING LẠI CÁC REQUEST VÀ RESPONSE
@Slf4j
@Component
public class LoggingFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, jakarta.servlet.ServletException {
        if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            logRequest(httpRequest);
        }

        chain.doFilter(request, response);

        if (response instanceof HttpServletResponse) {
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            logResponse(httpResponse);
        }
    }

    private void logRequest(HttpServletRequest request) {
        StringBuilder requestData = new StringBuilder();
        //LOG LAI REQUEST DATA
        requestData.append("REQUEST: [");
        requestData.append("METHOD=").append(request.getMethod());
        requestData.append(", PATH=").append(request.getRequestURI());
        // NEU LA CAC METHOD PUT HOAC POST SẼ ẨN ĐI BODY VÌ THƯỜNG CHỨA THÔNG TIN NHẠY CẢM
        if ("POST".equalsIgnoreCase(request.getMethod()) || "PUT".equalsIgnoreCase(request.getMethod())
                || "DELETE".equalsIgnoreCase(request.getMethod())) {
            requestData.append(", BODY=").append("SENSITIVE DATA HIDDEN");
        }
        requestData.append("]");

        log.info(requestData.toString());
    }

    //LOG DATA RESPONSE
    private void logResponse(HttpServletResponse response) {
        String responseData = "RESPONSE: [STATUS=" + response.getStatus() + "]";
        log.info(responseData);
    }
}