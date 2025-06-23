package ru.sem.spring.auth_service.service.exception;

public class AuthException extends RuntimeException {
    public AuthException(String message) {
        super(message);
    }
}
