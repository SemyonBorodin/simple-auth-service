package ru.sem.spring.auth_service.service;

import com.nimbusds.jose.JOSEException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.sem.spring.auth_service.dto.AuthenticationResponse;
import ru.sem.spring.auth_service.dto.LoginRequest;
import ru.sem.spring.auth_service.dto.RegisterRequest;
import ru.sem.spring.auth_service.model.User;
import ru.sem.spring.auth_service.service.exception.AuthException;
import ru.sem.spring.auth_service.service.exception.CannotSignJwtException;
import ru.sem.spring.auth_service.service.exception.InvalidRefreshTokenException;
import ru.sem.spring.auth_service.service.exception.InvalidTokenClaimsException;
import ru.sem.spring.auth_service.token.RefreshToken;
import ru.sem.spring.auth_service.token.TokenGenerator;
import ru.sem.spring.auth_service.token.TokenRepositoryService;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;

// оркестратор
@Service
public class AuthService implements AuthServiceInterface{
//    @Value("${jwt.refresh.ttl:7d}") константы заведи в конфиге и потом по всему проекту заменить
//    private Duration refreshTtl;
    private final TokenGenerator tokenGenerator;
    private final TokenRepositoryService tokenRepositoryService;
    private final UserService userService;
    private final RefreshTokenService refreshTokenService;

    public AuthService(TokenGenerator tokenGenerator, TokenRepositoryService tokenRepositoryService, UserService userService, RefreshTokenService refreshTokenService) {
        this.tokenGenerator = tokenGenerator;
        this.tokenRepositoryService = tokenRepositoryService;
        this.userService = userService;
        this.refreshTokenService = refreshTokenService;
    }

    private void saveRefreshToken(User user, AuthenticationResponse response) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(response.refreshToken());
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plus(Duration.ofDays(7)));
        tokenRepositoryService.save(refreshToken);
    }

    @Override
    @Transactional
    public AuthenticationResponse login(LoginRequest request) throws JOSEException, CannotSignJwtException, AuthException {
        var user = userService.authenticateUser(request);
        AuthenticationResponse response = tokenGenerator.createTokens(user);
        saveRefreshToken(user, response);
        return response;
    }

    @Override
    @Transactional
    public AuthenticationResponse register(RegisterRequest request) throws JOSEException, CannotSignJwtException {
        var user = userService.registerNewUser(request);
        AuthenticationResponse response = tokenGenerator.createTokens(user);
        saveRefreshToken(user, response);
        return response;
    }

    @Override
    @Transactional
    public AuthenticationResponse refresh(String refreshToken) throws InvalidTokenClaimsException, InvalidRefreshTokenException,
            ParseException, CannotSignJwtException, JOSEException {
        return refreshTokenService.refresh(refreshToken);
    }
}
