INSERT INTO role (id, name) VALUES (1, 'ROLE_ADMIN'), (2, 'ROLE_CA_USER'), (3, 'ROLE_END_USER')
    ON CONFLICT (id) DO NOTHING;

INSERT INTO users (email, password, name, surname, activated, enabled, creation_time, organization, last_password_reset_date, encrypted_user_symmetric_key, activation_token, activation_token_expiry) VALUES
                                                                                                                                                                                                           ('admin@example.com', '$2a$10$gP7WW.S5wGRk25KyBT/eG.u1x3zJPSrTSTMpIbe60G5tOr4TOUP4O', 'Admin', 'Adminovic', true, true, NOW(), 'System Administrators', NOW(), 'base64EnkriptovanKljucZaAdmina==', NULL, NULL),
                                                                                                                                                                                                           ('ca.user@example.com', '$2a$10$gP7WW.S5wGRk25KyBT/eG.u1x3zJPSrTSTMpIbe60G5tOr4TOUP4O', 'Pera', 'Peric', true, true, NOW(), 'UNS-FTN', NOW(), 'base64EnkriptovanKljucZaCaUsera==', NULL, NULL),
                                                                                                                                                                                                           ('end.user@example.com', '$2a$10$gP7WW.S5wGRk25KyBT/eG.u1x3zJPSrTSTMpIbe60G5tOr4TOUP4O', 'Mika', 'Mikic', true, true, NOW(), 'Client Company', NOW(), 'base64EnkriptovanKljucZaEndUsera==', NULL, NULL);
INSERT INTO user_role (user_id, role_id) VALUES
    (1, 1),
    (2, 2),
    (3, 3);

/* Administrator:
Email: admin@example.com
Lozinka: password
CA Korisnik:
Email: ca.user@example.com
Lozinka: password
Običan (End-User) Korisnik:
Email: end.user@example.com
Lozinka: password*/