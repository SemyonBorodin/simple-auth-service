package ru.sem.spring.auth_service.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.sem.spring.auth_service.model.User;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String username);
}
