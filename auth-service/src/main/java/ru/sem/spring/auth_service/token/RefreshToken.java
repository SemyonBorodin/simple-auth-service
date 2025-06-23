package ru.sem.spring.auth_service.token;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.stereotype.Service;
import ru.sem.spring.auth_service.model.User;

import java.time.Instant;
import java.util.UUID;

//@Table(name = "refresh_tokens")
@Entity
@Data
@Service
@Table(indexes = @Index(name = "idx_refresh_token_expiry", columnList = "expiryDate"))
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String token;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    private boolean revoked = false;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();
}