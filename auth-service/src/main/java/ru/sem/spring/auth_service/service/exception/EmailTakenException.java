package ru.sem.spring.auth_service.service.exception;

public class EmailTakenException extends Throwable {
    public EmailTakenException(String emailAlreadyRegistered) {
    }
}
