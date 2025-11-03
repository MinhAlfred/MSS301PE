package minhvq.apigateway_se181556.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
public class JwtAuthFilter implements WebFilter {
    private final String secret = "minhvoquangminhvoquangminhvoquangminhminhvoquangminhvoquangminhvoquangminh";
    private final SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        if (path.startsWith("/api/auth/login")) {
            return chain.filter(exchange);
        }
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)  // ✅ đúng cho JJWT 0.11.5
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            String userId = claims.getSubject(); // vì bạn lưu accountId trong subject
            String role = claims.get("role") != null ? claims.get("role").toString() : null;

            // bạn có thể thêm info vào header để downstream service dùng
            exchange.getRequest().mutate()
                    .header("X-USER-ID",userId)
                    .header("X-USER-ROLE", role)
                    .build();

            return chain.filter(
                    exchange.mutate()
                            .request(r -> r
                                    .header("X-USER-ID", userId)
                                    .header("X-USER-ROLE", role)
                            )
                            .build());

        } catch (Exception e) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }
}
