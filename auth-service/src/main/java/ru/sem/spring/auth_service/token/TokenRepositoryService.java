package ru.sem.spring.auth_service.token;

import org.springframework.stereotype.Component;
import ru.sem.spring.auth_service.repository.RefreshTokenRepository;

//@Value("${jwt.access.ttl:15m}") Duration accessTtl;
//@Value("${jwt.refresh.ttl:7d}") Duration refreshTtl;
@Component
public class TokenRepositoryService implements TokenRepositoryServiceInterface{
    private final RefreshTokenRepository refreshTokenRepo;

    public TokenRepositoryService(RefreshTokenRepository refreshTokenRepo) {
        this.refreshTokenRepo = refreshTokenRepo;
    }

    @Override
    public void save(RefreshToken refreshToken) {
        if (refreshToken == null) throw new IllegalArgumentException("RefreshToken cannot be null");
        refreshTokenRepo.saveAndFlush(refreshToken);
    }
}
