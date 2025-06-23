package ru.sem.spring.auth_service.dto;

import ru.sem.spring.auth_service.model.Role;

import java.util.Set;

public record RegistrationRequest(
        String username,
        String password,
        Set<Role> roles
) {}