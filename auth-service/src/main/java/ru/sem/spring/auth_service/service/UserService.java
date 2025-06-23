package ru.sem.spring.auth_service.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.sem.spring.auth_service.dto.LoginRequest;
import ru.sem.spring.auth_service.dto.RegisterRequest;
import ru.sem.spring.auth_service.model.Role;
import ru.sem.spring.auth_service.model.User;
import ru.sem.spring.auth_service.repository.UserRepository;
import ru.sem.spring.auth_service.service.exception.AuthException;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

// создание, валидация, поиск пользователей
@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder encoder;

    public UserService(UserRepository userRepository, PasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.encoder = encoder;
    }

    @Transactional // на случай варианта с flush
    public User registerNewUser(RegisterRequest request) {
        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new AuthException("Email already registered");
        }
        User user = buildUserFromRequest(request);
        return userRepository.save(user);
//        return userRepository.saveAndFlush(user); todo разберись с id и тем надо ли нам тут flush-ить все таки
    }

    private User buildUserFromRequest(RegisterRequest request) {
        User user = new User();
        user.setUsername(request.email());
        user.setEmail(request.email());
        user.setPassword(encoder.encode(request.password()));
        user.setEnabled(true);
        user.setRoles(Set.of(Role.ROLE_USER));

        return user;
    }

    public User authenticateUser(LoginRequest request) {
        var user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new AuthException("User not found"));

        if (!encoder.matches(request.password(), user.getPassword())) {
            throw new AuthException("Invalid password");
        }
        if (!user.isEnabled()) {
            throw new AuthException("User is disabled");
        }
        return user;
    }

    public Optional<User> findById(String userId) {
        return userRepository.findById(UUID.fromString(userId));
    }
}
