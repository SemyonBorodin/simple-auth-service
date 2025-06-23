package ru.sem.spring.auth_service.token;

import com.nimbusds.jose.JOSEException;
import ru.sem.spring.auth_service.dto.AuthenticationResponse;
import ru.sem.spring.auth_service.model.User;
import ru.sem.spring.auth_service.service.exception.CannotSignJwtException;

public interface TokenFactory {
    AuthenticationResponse createTokens(User user) throws JOSEException, CannotSignJwtException;
    String createAccessToken(User user) throws CannotSignJwtException, JOSEException;
    RefreshToken createRefreshToken(User user) throws CannotSignJwtException, JOSEException;
}