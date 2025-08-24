INSERT INTO role (id, name) VALUES
                                (1, 'ROLE_ADMIN'),
                                (2, 'ROLE_CA_USER'),
                                (3, 'ROLE_END_USER')
    ON CONFLICT (id) DO NOTHING;

INSERT INTO users (email, password, name, surname, activated, enabled, creation_time, organization, last_password_reset_date, encrypted_user_symmetric_key, activation_token, activation_token_expiry) VALUES
                                                                                                                                                                                                           ('admin@example.com', '$2a$10$XyXL3ErdT34a1hNoquFtHOaQ8tCMloitD1pE1Uil5DVOrMUmfkrNe', 'Admin', 'Adminovic', true, true, NOW(), 'System Administrators', NOW(), 'ZSpGLj6xr7JnxX1jIDQYowCby+aMIFOo7+Y+46cTSio=', NULL, NULL),
                                                                                                                                                                                                           ('ca.user@example.com', '$2a$10$XyXL3ErdT34a1hNoquFtHOaQ8tCMloitD1pE1Uil5DVOrMUmfkrNe', 'Pera', 'Peric', true, true, NOW(), 'UNS-FTN', NOW(), 'ZSpGLj6xr7JnxX1jIDQYowCby+aMIFOo7+Y+46cTSio=', NULL, NULL),
                                                                                                                                                                                                           ('end.user@example.com', '$2a$10$XyXL3ErdT34a1hNoquFtHOaQ8tCMloitD1pE1Uil5DVOrMUmfkrNe', 'Mika', 'Mikic', true, true, NOW(), 'Client Company', NOW(), 'ZSpGLj6xr7JnxX1jIDQYowCby+aMIFOo7+Y+46cTSio=', NULL, NULL),
                                                                                                                                                                                                           ('ca.user2@example.com', '$2a$10$XyXL3ErdT34a1hNoquFtHOaQ8tCMloitD1pE1Uil5DVOrMUmfkrNe', 'Ana', 'Anic', true, true, NOW(), 'Elektrotehnicki Fakultet', NOW(), 'ZSpGLj6xr7JnxX1jIDQYowCby+aMIFOo7+Y+46cTSio=', NULL, NULL),
                                                                                                                                                                                                           ('ca.user3@example.com', '$2a$10$XyXL3ErdT34a1hNoquFtHOaQ8tCMloitD1pE1Uil5DVOrMUmfkrNe', 'Jovan', 'Jovanovic', true, true, NOW(), 'Medicinski Fakultet', NOW(), 'ZSpGLj6xr7JnxX1jIDQYowCby+aMIFOo7+Y+46cTSio=', NULL, NULL);

INSERT INTO user_role (user_id, role_id) VALUES
                                             (1, 1),  -- admin@example.com
                                             (2, 2),  -- 
                                             (3, 3),  -- end.user@example.com
                                             (4, 2),  -- ca.user2@example.com
                                             (5, 2);   -- ca.user3@example.com


-- Sve lozinke su pass1232111

INSERT INTO certificates (
     serial_number, valid_from, valid_to, type, issuer_id, owner_id,
    is_revoked, revocation_reason, keystore_file_name, encrypted_keystore_password
) VALUES
      ( '1756070448121', '2025-08-24 02:00:00', '2027-10-24 02:00:00', 'ROOT', NULL, 2, false, NULL, '1756070448121.jks', '0Y75ilK97GjjyOZ4TeRPYU/68Hu7grf3gGpg2R6R5qw='),
      ( '1756070521659', '2025-08-24 02:00:00', '2026-12-24 01:00:00', 'INTERMEDIATE', 1, 2, false, NULL, '1756070521659.jks', 'Pzxe957Lhj7qcOKRNml7hWqfZUERK7GcmICnZLwjbrc='),
      ( '1756070621656', '2025-08-24 02:00:00', '2026-08-24 02:00:00', 'END_ENTITY', 2, 2, false, NULL, '1756070621656.jks', 'JHdg9WBf6OXH8HfGOKxxrJidxbQHgx0PK3XMkDzuT6c='),
      ( '1756070692229', '2025-08-24 02:00:00', '2026-04-29 02:00:00', 'INTERMEDIATE', 2, 2, false, NULL, '1756070692229.jks', 'RvoO8y/iG8Rrg0ozhW5Fxhe1wrvPk6Hx7m6aSCZflhs='),
      ( '1756071279231', '2025-08-24 02:00:00', '2027-10-24 02:00:00', 'ROOT', NULL, 4, false, NULL, '1756071279231.jks', 'ZX1eU+PwM9xP8UkVZiSTQWjlt4fTT/w8PVg09tXuv5k=');


