package exe2.mssapp.msaccount_se181556.util;

import exe2.mssapp.msaccount_se181556.model.SystemAccounts;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {
    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private long expirationMs;

    private Key signingKey;

    @PostConstruct
    public void init() {
        byte[] keyBytes = jwtSecret.getBytes();
        signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(SystemAccounts account) {
        long now = System.currentTimeMillis();
        Date issuedAt = new Date(now);
        Date expiry = new Date(now + expirationMs);

        return Jwts.builder()
                .setSubject(String.valueOf(account.getAccountId()))
                .claim("email", account.getEmail())
                .claim("role", account.getRole())
                .claim("roleId", account.getRole())
                .claim("isActive", account.isActive())
                .setIssuedAt(issuedAt)
                .setExpiration(expiry)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }
}
