package ru.sem.spring.auth_service.service.exception;

public class CannotSignJwtException extends Throwable {
    public CannotSignJwtException(String failedToSignToken) {
    }
}
