package ru.sem.spring.auth_service.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.sem.spring.auth_service.dto.AuthenticationResponse;
import ru.sem.spring.auth_service.dto.LoginRequest;
import ru.sem.spring.auth_service.dto.RefreshRequest;
import ru.sem.spring.auth_service.dto.RegisterRequest;
import ru.sem.spring.auth_service.service.AuthService;
import ru.sem.spring.auth_service.service.exception.CannotSignJwtException;
import ru.sem.spring.auth_service.service.exception.InvalidRefreshTokenException;
import ru.sem.spring.auth_service.service.exception.InvalidTokenClaimsException;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody LoginRequest request) {
        try {
            return ResponseEntity.ok(authService.login(request));
        } catch (Exception | CannotSignJwtException e) {
            return ResponseEntity.status(401).body(null);
        }
    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
        try {
            return ResponseEntity.ok(authService.register(request));
        } catch (Exception | CannotSignJwtException e) {
            return ResponseEntity.status(400).body(null);
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponse> refresh(@RequestBody RefreshRequest request) {
        try {
            return ResponseEntity.ok(authService.refresh(request.refreshToken()));
        } catch (Exception | InvalidRefreshTokenException | InvalidTokenClaimsException | CannotSignJwtException e) {
            return ResponseEntity.status(401).body(null);
        }
    }
}