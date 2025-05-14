package com.mtran.mvc.config.utils.jwt;

import com.mtran.mvc.config.utils.RSAKeyUtil;
import com.mtran.mvc.dto.request.LogoutRequest;
import com.mtran.mvc.dto.request.RefreshRequest;
import com.mtran.mvc.entity.InvalidateToken;
import com.mtran.mvc.entity.User;
import com.mtran.mvc.repository.InvalidatedTokenRepository;
import com.mtran.mvc.repository.UserRepository;
import com.mtran.mvc.service.impl.TokenServiceImpl;
import com.mtran.mvc.support.AppException;
import com.mtran.mvc.support.ErrorCode;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Component
public class JwtUtil {
    private static final long EXPIRATION_TIME_TOKEN = 3600000L;//1 giờ
    private static final long EXPIRATION_TIME_REFRESH_TOKEN = 604800000L;// 7 ngày
    private final RSAKeyUtil rsaKeyUtil;
    private final UserRepository userRepository;
    private final InvalidatedTokenRepository invalidatedTokenRepository;
    private final StringRedisTemplate redisTemplate;
    private final TokenServiceImpl tokenServiceImpl;

    public JwtUtil(RSAKeyUtil rsaKeyUtil, InvalidatedTokenRepository invalidatedTokenRepository,
                   UserRepository userRepository, StringRedisTemplate redisTemplate, TokenServiceImpl tokenServiceImpl) {
        this.rsaKeyUtil = rsaKeyUtil;
        this.invalidatedTokenRepository = invalidatedTokenRepository;
        this.userRepository = userRepository;
        this.redisTemplate = redisTemplate;
        this.tokenServiceImpl = tokenServiceImpl;
    }

    // tao token
    public String generateToken(String username) throws Exception {
        PrivateKey privateKey = rsaKeyUtil.getPrivateKey();

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME_TOKEN))
                .setId(UUID.randomUUID().toString())
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    //tạo refresh token
    public String generateRefreshToken(String username) throws Exception {
        PrivateKey privateKey = rsaKeyUtil.getPrivateKey();
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME_REFRESH_TOKEN))
                .setId(UUID.randomUUID().toString())
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    //  refresh access token ( email duoc dung lam usernam)
    public String refreshToken(RefreshRequest RefreshRequest) throws Exception {
        String email = RefreshRequest.getEmail();
        String accessToken= tokenServiceImpl.getAccessToken(email);
        var signJWT = validateToken(accessToken);
        String jit = signJWT.getId();
        Date expiryTime = signJWT.getExpiration();

        InvalidateToken invalidateToken = InvalidateToken.builder()
                .id(jit)
                .expiryTime(expiryTime)
                .build();
        invalidatedTokenRepository.save(invalidateToken);
        return generateToken(email);
    }

    // kiem tra token
    public Claims validateToken(String token) throws Exception {

        PublicKey publicKey = rsaKeyUtil.getPublicKey();
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        if (invalidatedTokenRepository.existsById(claims.getId())) {
            throw new AppException(ErrorCode.INVALID_KEY);
        }

        if (Boolean.TRUE.equals(redisTemplate.hasKey("invalid_token:" + claims.getId()))) {
            throw new AppException(ErrorCode.INVALID_KEY);
        }
        String email = claims.getSubject();
        User user = userRepository.findByEmail(email);
        //check issueAt so với lastchangePassword để xác thực được token còn hiệu lực hay không
        LocalDateTime lastChangePassword = user.getLastChangePassword();
        if (lastChangePassword != null) {
            Date issuedAt = claims.getIssuedAt();
            LocalDateTime issuedAtTime = issuedAt.toInstant()
                    .atZone(ZoneId.systemDefault())
                    .toLocalDateTime();
            if (issuedAtTime.isBefore(lastChangePassword)) {
                throw new AppException(ErrorCode.INVALID_KEY);
            }
        }
        return claims;
    }

    //vo hieu hoa ca access token va refresh token
    public void logout(LogoutRequest request) throws Exception {
        //access token
        if (request.getToken() != null) {
            var signToken = validateToken(request.getToken());

            String jit = signToken.getId();
            Date expiryTime = signToken.getExpiration();
            /* CÁCH LƯU BLACKLIST DATABASE
            InvalidateToken invalidateToken = InvalidateToken.builder()
                    .id(jit)
                    .expiryTime(expiryTime)
                    .build();
            invalidatedTokenRepository.save(invalidateToken);
             */
            long TTL = (expiryTime.getTime() - System.currentTimeMillis()) / 1000;
            redisTemplate.opsForValue().set("invalid_token:" + jit, jit, TTL, TimeUnit.SECONDS);
        }
        //refresh token
        if (request.getRefreshToken() != null) {
            var refreshSignToken = validateToken(request.getRefreshToken());
            String refreshJit = refreshSignToken.getId();
            Date refreshExpiryTime = refreshSignToken.getExpiration();
            /*  CÁCH LƯU BLACKLIST DATABASE
            InvalidateToken refreshInvalidateToken = InvalidateToken.builder()
                    .id(refreshJit)
                    .expiryTime(refreshExpiryTime)
                    .build();
            invalidatedTokenRepository.save(refreshInvalidateToken);
             */
            long TTL = (refreshExpiryTime.getTime() - System.currentTimeMillis()) / 1000;
            redisTemplate.opsForValue().set("invalid_token:" + refreshJit, refreshJit, TTL, TimeUnit.SECONDS);
        }
    }

    //lay ra email(unique) cua nguoi dung tu token
    public String extractEmail(String token) throws Exception {
        PublicKey publicKey = rsaKeyUtil.getPublicKey();
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }
}

