package ru.sem.spring.auth_service.service.exception;

public class InvalidRefreshTokenException extends Throwable {
    public InvalidRefreshTokenException(String invalidRefreshToken) {
    }
}
