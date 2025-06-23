package ru.sem.spring.auth_service.service;

import com.nimbusds.jose.JOSEException;
import ru.sem.spring.auth_service.service.exception.CannotSignJwtException;

import java.text.ParseException;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;

public interface JwtService {
    String generateToken(Map<String, Object> claims, String subject, Duration ttl) throws JOSEException, CannotSignJwtException;

    boolean isValid(String token) throws ParseException, JOSEException;

    Optional<String> extractSubject(String token) throws ParseException;

    Optional<Map<String, Object>> extractAllClaims(String token) throws ParseException;

}