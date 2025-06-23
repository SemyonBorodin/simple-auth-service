package ru.sem.spring.auth_service.token;

import com.nimbusds.jose.JOSEException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import ru.sem.spring.auth_service.dto.AuthenticationResponse;
import ru.sem.spring.auth_service.model.User;
import ru.sem.spring.auth_service.service.JwtService;
import ru.sem.spring.auth_service.service.exception.CannotSignJwtException;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

@Component
public class TokenGenerator implements TokenFactory {
    @Value("${jwt.expiration.access:15m}")
    private Duration accessTtl;
    @Value("${jwt.expiration.refresh:7d}")
    private Duration refreshTtl;

    private final JwtService jwtService;

    public TokenGenerator(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public String createAccessToken(User user) throws CannotSignJwtException, JOSEException {
        Map<String, Object> claims = Map.of(
                "type", TokenType.ACCESS,
                "email", user.getEmail(),
                "roles", user.getRoles()
        );
        return jwtService.generateToken(claims, user.getId().toString(), accessTtl);
    }

    @Override
    public RefreshToken createRefreshToken(User user) throws CannotSignJwtException, JOSEException {
        String tokenValue = jwtService.generateToken(
                Map.of("type", TokenType.REFRESH),
                user.getId().toString(),
                refreshTtl
        );
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(tokenValue);
        refreshToken.setUser(user);
        refreshToken.setCreatedAt(Instant.now());
        refreshToken.setRevoked(false);
        refreshToken.setExpiryDate(Instant.now().plus(refreshTtl));
        return refreshToken;
    }

    @Override
    public AuthenticationResponse createTokens(User user) throws JOSEException, CannotSignJwtException {
        String accessToken = createAccessToken(user);
        RefreshToken refreshToken = createRefreshToken(user);
        return new AuthenticationResponse(accessToken, refreshToken.getToken());
    }
}
