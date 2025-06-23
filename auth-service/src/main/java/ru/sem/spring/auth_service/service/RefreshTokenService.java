package ru.sem.spring.auth_service.service;

import com.nimbusds.jose.JOSEException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import ru.sem.spring.auth_service.dto.AuthenticationResponse;
import ru.sem.spring.auth_service.model.User;
import ru.sem.spring.auth_service.repository.RefreshTokenRepository;
import ru.sem.spring.auth_service.service.exception.CannotSignJwtException;
import ru.sem.spring.auth_service.service.exception.InvalidRefreshTokenException;
import ru.sem.spring.auth_service.token.RefreshToken;
import ru.sem.spring.auth_service.token.TokenGenerator;
import ru.sem.spring.auth_service.token.TokenRepositoryService;
import ru.sem.spring.auth_service.token.TokenType;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;

@Service
public class RefreshTokenService {
    private static final Logger LOGGER = LoggerFactory.getLogger(RefreshTokenService.class);

    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserService userService;
    private final TokenGenerator tokenGenerator;
    private final TokenRepositoryService tokenRepositoryService;

    public RefreshTokenService
            (JwtService jwtService,
             RefreshTokenRepository refreshTokenRepository,
             UserService userService,
             TokenGenerator tokenGenerator, TokenRepositoryService tokenRepositoryService) {
        this.jwtService = jwtService;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userService = userService;
        this.tokenGenerator = tokenGenerator;
        this.tokenRepositoryService = tokenRepositoryService;
    }

    public AuthenticationResponse refresh(String refreshToken)
            throws ParseException, JOSEException, InvalidRefreshTokenException, CannotSignJwtException {

        validateRefreshToken(refreshToken);
        var user = extractUserFromToken(refreshToken);
        revokeRefreshToken(refreshToken);

        AuthenticationResponse response = tokenGenerator.createTokens(user);
        RefreshToken newRefreshToken = new RefreshToken();
        newRefreshToken.setToken(response.refreshToken());
        newRefreshToken.setUser(user);
        newRefreshToken.setCreatedAt(Instant.now());
        newRefreshToken.setExpiryDate(Instant.now().plus(Duration.ofDays(7)));
        tokenRepositoryService.save(newRefreshToken);

        return response;
    }

    private void validateRefreshToken(String token) throws ParseException, JOSEException, InvalidRefreshTokenException {
        if (!jwtService.isValid(token)) {
            LOGGER.warn("Invalid JWT signature or expired token");
            throw new InvalidRefreshTokenException("Invalid token");
        }
        if (!isRefreshToken(token)) {
            LOGGER.warn("Attempt to use non-refresh token");
            throw new InvalidRefreshTokenException("Not a refresh token");
        }
        if (isTokenRevoked(token)) {
            LOGGER.warn("Attempt to use revoked token");
            throw new InvalidRefreshTokenException("Token revoked");
        }
    }

    private boolean isRefreshToken(String token) {
        try {
            return jwtService.extractAllClaims(token)
                    .map(claims -> "REFRESH".equals(claims.get("type")))
                    .orElse(false);
        } catch (Exception e) {
            LOGGER.error("Token type check failed", e);
            return false;
        }
    }

    private boolean isTokenRevoked(String token) {
        return refreshTokenRepository.findByToken(token)
                .map(refreshToken ->
                        refreshToken.isRevoked() ||
                                refreshToken.getExpiryDate().isBefore(Instant.now())
                ).orElse(true);
    }

    private User extractUserFromToken(String token)
            throws ParseException, InvalidRefreshTokenException {
        return jwtService.extractSubject(token)
                .flatMap(userService::findById)
                .orElseThrow(() -> new InvalidRefreshTokenException("User not found"));
    }

    private void revokeRefreshToken(String token) {
        refreshTokenRepository.findByToken(token)
                .ifPresent(refreshToken -> {
                    refreshToken.setRevoked(true);
                    refreshTokenRepository.save(refreshToken);
                    LOGGER.debug("Token revoked for user {}", refreshToken.getUser().getId());
                });
    }
}
