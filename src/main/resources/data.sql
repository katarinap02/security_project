INSERT INTO role (id, name) VALUES
                                (1, 'ROLE_ADMIN'),
                                (2, 'ROLE_CA_USER'),
                                (3, 'ROLE_END_USER')
    ON CONFLICT (id) DO NOTHING;

INSERT INTO users (email, password, name, surname, activated, enabled, creation_time, organization, last_password_reset_date, encrypted_user_symmetric_key, activation_token, activation_token_expiry) VALUES
                                                                                                                                                                                                           ('admin@example.com', '$2a$10$XyXL3ErdT34a1hNoquFtHOaQ8tCMloitD1pE1Uil5DVOrMUmfkrNe', 'Admin', 'Adminovic', true, true, NOW(), 'System Administrators', NOW(), 'ZSpGLj6xr7JnxX1jIDQYowCby+aMIFOo7+Y+46cTSio=', NULL, NULL),
--                                                                                                                                                                                                            ('ca.user@example.com', '$2a$10$XyXL3ErdT34a1hNoquFtHOaQ8tCMloitD1pE1Uil5DVOrMUmfkrNe', 'Pera', 'Peric', true, true, NOW(), 'UNS-FTN', NOW(), 'ZSpGLj6xr7JnxX1jIDQYowCby+aMIFOo7+Y+46cTSio=', NULL, NULL),
                                                                                                                                                                                                           ('ca.user@example.com', '$2a$10$XyXL3ErdT34a1hNoquFtHOaQ8tCMloitD1pE1Uil5DVOrMUmfkrNe', 'Pera', 'Peric', true, true, NOW(), 'UNS-FTN', NOW(), 'ZSpGLj6xr7JnxX1jIDQYowCby+aMIFOo7+Y+46cTSio=', NULL, NULL),
                                                                                                                                                                                                           ('end.user@example.com', '$2a$10$XyXL3ErdT34a1hNoquFtHOaQ8tCMloitD1pE1Uil5DVOrMUmfkrNe', 'Mika', 'Mikic', true, true, NOW(), 'Client Company', NOW(), 'ZSpGLj6xr7JnxX1jIDQYowCby+aMIFOo7+Y+46cTSio=', NULL, NULL),
--                                                                                                                                                                                                            ('ca.user2@example.com', '$2a$10$XyXL3ErdT34a1hNoquFtHOaQ8tCMloitD1pE1Uil5DVOrMUmfkrNe', 'Ana', 'Anic', true, true, NOW(), 'Elektrotehnicki Fakultet', NOW(), 'ZSpGLj6xr7JnxX1jIDQYowCby+aMIFOo7+Y+46cTSio=', NULL, NULL),
                                                                                                                                                                                                           ('ca.user2@example.com', '$2a$10$XyXL3ErdT34a1hNoquFtHOaQ8tCMloitD1pE1Uil5DVOrMUmfkrNe', 'Ana', 'Anic', true, true, NOW(), 'Elektrotehnicki Fakultet', NOW(), 'ZSpGLj6xr7JnxX1jIDQYowCby+aMIFOo7+Y+46cTSio=', NULL, NULL),
                                                                                                                                                                                                           ('ca.user3@example.com', '$2a$10$XyXL3ErdT34a1hNoquFtHOaQ8tCMloitD1pE1Uil5DVOrMUmfkrNe', 'Jovan', 'Jovanovic', true, true, NOW(), 'Medicinski Fakultet', NOW(), 'ZSpGLj6xr7JnxX1jIDQYowCby+aMIFOo7+Y+46cTSio=', NULL, NULL);

INSERT INTO user_role (user_id, role_id) VALUES
                                             (1, 1),  -- admin@example.com
                                             (2, 2),  -- 
                                             (3, 3),  -- end.user@example.com
                                             (4, 2),  -- ca.user2@example.com
                                             (5, 2);   -- ca.user3@example.com


-- Sve lozinke su pass1232111

/*INSERT INTO certificates (
     serial_number, valid_from, valid_to, type, issuer_id, owner_id,
    is_revoked, revocation_reason, keystore_file_name, encrypted_keystore_password
) VALUES
      ( '1756070448121', '2025-08-24 02:00:00', '2027-10-24 02:00:00', 'ROOT', NULL, 2, false, NULL, '1756070448121.jks', '0Y75ilK97GjjyOZ4TeRPYU/68Hu7grf3gGpg2R6R5qw='),
      ( '1756070521659', '2025-08-24 02:00:00', '2026-12-24 01:00:00', 'INTERMEDIATE', 1, 2, false, NULL, '1756070521659.jks', 'Pzxe957Lhj7qcOKRNml7hWqfZUERK7GcmICnZLwjbrc='),
      ( '1756070621656', '2025-08-24 02:00:00', '2026-08-24 02:00:00', 'END_ENTITY', 2, 2, false, NULL, '1756070621656.jks', 'JHdg9WBf6OXH8HfGOKxxrJidxbQHgx0PK3XMkDzuT6c='),
      ( '1756070692229', '2025-08-24 02:00:00', '2026-04-29 02:00:00', 'INTERMEDIATE', 2, 2, false, NULL, '1756070692229.jks', 'RvoO8y/iG8Rrg0ozhW5Fxhe1wrvPk6Hx7m6aSCZflhs='),
      ( '1756071279231', '2025-08-24 02:00:00', '2027-10-24 02:00:00', 'ROOT', NULL, 4, false, NULL, '1756071279231.jks', 'ZX1eU+PwM9xP8UkVZiSTQWjlt4fTT/w8PVg09tXuv5k=');
*//*
INSERT INTO certificates (
    serial_number, valid_from, valid_to, type, issuer_id, owner_id,
    is_revoked, revocation_reason, keystore_file_name, encrypted_keystore_password
) VALUES
    ('1692951375401', '2025-08-24 02:00:00', '2035-08-24 02:00:00', 'ROOT', NULL, 2, false, NULL, 'root1.jks',
     'Jny8Mf0bGTRzuKA7uF0pHMLQBa/Lyve1X3SGoz6QFLs=')

--     ('1692951375401', '2025-08-24 02:00:00', '2035-08-24 02:00:00', 'ROOT', NULL, 2, false, NULL, 'root1.jks', 'Jny8Mf0bGTRzuKA7uF0pHMLQBa/Lyve1X3SGoz6QFLs='),
      ('1692951375403', '2025-08-24 02:00:00', '2027-08-24 02:00:00', 'INTERMEDIATE', 1, 4, false, NULL, 'intermediate1.jks', 'y3uKItT7gmVA6cNHYslEwMLQBa/Lyve1X3SGoz6QFLs='),
      ('1756070621656', '2025-08-24 02:00:00', '2026-08-24 02:00:00', 'END_ENTITY', 2, 2, false, NULL, '1756070621656.jks', 'JHdg9WBf6OXH8HfGOKxxrJidxbQHgx0PK3XMkDzuT6c='),
      ('1756070692229', '2025-08-24 02:00:00', '2026-04-29 02:00:00', 'INTERMEDIATE', 2, 2, false, NULL, '1756070692229.jks', 'RvoO8y/iG8Rrg0ozhW5Fxhe1wrvPk6Hx7m6aSCZflhs='),
      ('1756071279231', '2025-08-24 02:00:00', '2035-08-24 02:00:00', 'ROOT', NULL, 4, false, NULL, '1756071279231.jks', 'ZX1eU+PwM9xP8UkVZiSTQWjlt4fTT/w8PVg09tXuv5k=');


INSERT INTO ca (name, max_certificate_duration, certificate_bytes, private_key_bytes, keystore_file_name, keystore_password, key_password, is_root, serial_number)
VALUES
--     ('CA Root 1', 3650, NULL, NULL, 'keystores/root1.jks', 'Jny8Mf0bGTRzuKA7uF0pHMLQBa/Lyve1X3SGoz6QFLs=', 'Jny8Mf0bGTRzuKA7uF0pHMLQBa/Lyve1X3SGoz6QFLs=', true, '1692951375401'),
('CA Root 1', 3650, NULL, NULL, 'keystores/root1.jks',
 'Jny8Mf0bGTRzuKA7uF0pHMLQBa/Lyve1X3SGoz6QFLs=',  -- keystore_password
 'Jny8Mf0bGTRzuKA7uF0pHMLQBa/Lyve1X3SGoz6QFLs=',  -- key_password
 true, '1692951375401')
    ('CA Intermediate 1', 1825, NULL, NULL, 'keystores/intermediate1.jks', 'y3uKItT7gmVA6cNHYslEwMLQBa/Lyve1X3SGoz6QFLs=', 'y3uKItT7gmVA6cNHYslEwMLQBa/Lyve1X3SGoz6QFLs=', false, '1692951375403');


INSERT INTO csr (created_at, csr_pem, public_key, requested_validity_days, status, subject, type, ca_id, user_id)
VALUES
    ('2025-08-27 03:12:25.086693', '84788', '84789', 90, 'PENDING', '84790', 'CA', 1, 1);
*/


INSERT INTO ca (name, max_certificate_duration, certificate_bytes, private_key_bytes, keystore_file_name, keystore_password, key_password, is_root, serial_number)
VALUES
    ('CA Root 1', 3650, NULL, NULL, 'keystores/root1.jks', '4GB4bbTlF7TctzVUluJB1lcxTRNqAcncE62YaLjgIC0=', '4GB4bbTlF7TctzVUluJB1lcxTRNqAcncE62YaLjgIC0=', true, '1692951375401'),
    ('CA Intermediate 1', 1825, NULL, NULL, 'keystores/intermediate1.jks', 'JQaqb5R/bs0bZw3W3VGdFVcxTRNqAcncE62YaLjgIC0=', 'JQaqb5R/bs0bZw3W3VGdFVcxTRNqAcncE62YaLjgIC0=', false, '1692951375403');

-- Certificates
INSERT INTO certificates (
    serial_number, valid_from, valid_to, type, issuer_id, owner_id,
    is_revoked, revocation_reason, keystore_file_name, encrypted_keystore_password
)
VALUES
    ('1692951375401', '2025-08-24 02:00:00', '2035-08-24 02:00:00', 'ROOT', NULL, 2, false, NULL, 'root1.jks', '4GB4bbTlF7TctzVUluJB1lcxTRNqAcncE62YaLjgIC0='),
    ('1692951375403', '2025-08-24 02:00:00', '2027-08-24 02:00:00', 'INTERMEDIATE', 1, 4, false, NULL, 'intermediate1.jks', 'JQaqb5R/bs0bZw3W3VGdFVcxTRNqAcncE62YaLjgIC0='),
    ('1756070621656', '2025-08-24 02:00:00', '2026-08-24 02:00:00', 'END_ENTITY', 2, 2, false, NULL, '1756070621656.jks', 'JHdg9WBf6OXH8HfGOKxxrJidxbQHgx0PK3XMkDzuT6c='),
    ('1756070692229', '2025-08-24 02:00:00', '2026-04-29 02:00:00', 'INTERMEDIATE', 2, 2, false, NULL, '1756070692229.jks', 'RvoO8y/iG8Rrg0ozhW5Fxhe1wrvPk6Hx7m6aSCZflhs='),
    ('1756071279231', '2025-08-24 02:00:00', '2035-08-24 02:00:00', 'ROOT', NULL, 4, false, NULL, '1756071279231.jks', 'ZX1eU+PwM9xP8UkVZiSTQWjlt4fTT/w8PVg09tXuv5k=');

-- CSR (primer)
INSERT INTO csr (created_at, csr_pem, public_key, requested_validity_days, status, subject, type, ca_id, user_id)
VALUES
    ('2025-08-27 03:12:25.086693', '84788', '84789', 90, 'PENDING', '84790', 'CA', 1, 1);

