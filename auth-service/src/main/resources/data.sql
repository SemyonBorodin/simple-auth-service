INSERT INTO t_user (id, username, email, password, enabled, created_at)
VALUES
    ('550e8400-e29b-41d4-a716-446655440000', 'admin', 'admin@example.com', '$2a$10$xJwasdasdasdas', true, CURRENT_TIMESTAMP),
    ('3fa85f64-5717-4562-b3fc-2c963f66afa6', 'user', 'user@example.com', '$2a$10$yTnadaasdsadsdasdad', true, CURRENT_TIMESTAMP);