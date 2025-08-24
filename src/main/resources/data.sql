INSERT INTO role (id, name) VALUES (1, 'ROLE_ADMIN'), (2, 'ROLE_CA_USER'), (3, 'ROLE_END_USER')
    ON CONFLICT (id) DO NOTHING;

INSERT INTO users (email, password, name, surname, activated, enabled, creation_time, organization, last_password_reset_date, encrypted_user_symmetric_key, activation_token, activation_token_expiry) VALUES
                                                                                                                                                                                                           ('admin@example.com', '$2a$10$XyXL3ErdT34a1hNoquFtHOaQ8tCMloitD1pE1Uil5DVOrMUmfkrNe', 'Admin', 'Adminovic', true, true, NOW(), 'System Administrators', NOW(), 'ZSpGLj6xr7JnxX1jIDQYowCby+aMIFOo7+Y+46cTSio=', NULL, NULL),
                                                                                                                                                                                                           ('ca.user@example.com', '$2a$10$XyXL3ErdT34a1hNoquFtHOaQ8tCMloitD1pE1Uil5DVOrMUmfkrNe', 'Pera', 'Peric', true, true, NOW(), 'UNS-FTN', NOW(), 'ZSpGLj6xr7JnxX1jIDQYowCby+aMIFOo7+Y+46cTSio=', NULL, NULL),
                                                                                                                                                                                                           ('end.user@example.com', '$2a$10$XyXL3ErdT34a1hNoquFtHOaQ8tCMloitD1pE1Uil5DVOrMUmfkrNe', 'Mika', 'Mikic', true, true, NOW(), 'Client Company', NOW(), 'ZSpGLj6xr7JnxX1jIDQYowCby+aMIFOo7+Y+46cTSio=', NULL, NULL);
INSERT INTO user_role (user_id, role_id) VALUES
    (1, 1),
    (2, 2),
    (3, 3);

/* Administrator:
Email: admin@example.com
Lozinka: pass1232111
CA Korisnik:
Email: ca.user@example.com
Lozinka: pass1232111
Običan (End-User) Korisnik:
Email: end.user@example.com
Lozinka: pass1232111*/