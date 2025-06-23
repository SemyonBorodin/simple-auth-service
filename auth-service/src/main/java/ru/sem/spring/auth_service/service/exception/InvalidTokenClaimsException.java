package ru.sem.spring.auth_service.service.exception;

public class InvalidTokenClaimsException extends Throwable {
    public InvalidTokenClaimsException(String invalidTokenClaims) {
    }
}
