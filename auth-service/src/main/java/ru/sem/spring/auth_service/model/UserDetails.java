package ru.sem.spring.auth_service.model;

import java.util.Set;
import java.util.UUID;

public interface UserDetails {
    UUID getId();
    String getEmail();
    String getPassword();
    Set<Role> getRoles();
    boolean isEnabled();
}