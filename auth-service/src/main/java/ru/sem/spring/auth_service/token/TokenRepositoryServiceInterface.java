package ru.sem.spring.auth_service.token;

public interface TokenRepositoryServiceInterface {
    void save(RefreshToken refreshToken);
}
