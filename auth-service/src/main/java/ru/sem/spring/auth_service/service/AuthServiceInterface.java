package ru.sem.spring.auth_service.service;

import com.nimbusds.jose.JOSEException;
import ru.sem.spring.auth_service.dto.AuthenticationResponse;
import ru.sem.spring.auth_service.dto.LoginRequest;
import ru.sem.spring.auth_service.dto.RegisterRequest;
import ru.sem.spring.auth_service.service.exception.AuthException;
import ru.sem.spring.auth_service.service.exception.CannotSignJwtException;
import ru.sem.spring.auth_service.service.exception.InvalidRefreshTokenException;
import ru.sem.spring.auth_service.service.exception.InvalidTokenClaimsException;

import java.text.ParseException;

public interface AuthServiceInterface {
    AuthenticationResponse login(LoginRequest request) throws JOSEException, CannotSignJwtException, AuthException;

    AuthenticationResponse register(RegisterRequest request) throws JOSEException, CannotSignJwtException;

    AuthenticationResponse refresh(String refreshToken) throws InvalidTokenClaimsException, InvalidRefreshTokenException, ParseException, CannotSignJwtException, JOSEException;
}
