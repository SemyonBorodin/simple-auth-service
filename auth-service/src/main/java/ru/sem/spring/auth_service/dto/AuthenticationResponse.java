package ru.sem.spring.auth_service.dto;

public record AuthenticationResponse(String accessToken, String refreshToken) {
}
