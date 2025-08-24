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

INSERT INTO certificates (id, encrypted_keystore_password, is_revoked, keystore_file_name, revocation_reason, serial_number, type, valid_from, valid_to, issuer_id, owner_id) VALUES
                                                                                                                                                                                  (1, 'PLQgxAFi9uAqqbuopRjizqsSiK21zT+5HD0DoEMcaeIo=', false, '1756053616451.jks', NULL, '1756053616451', 'ROOT', '2025-08-24 02:00:00', '2027-05-24 02:00:00', 1, 1),
                                                                                                                                                                                  (2, 'NcRFkf1ZjNoKQAgdB9UcSTrujUhjp9mxHBL1/04lEAU=', false, '1756053672999.jks', NULL, '1756053672999', 'INTERMEDIATE', '2025-08-24 02:00:00', '2026-08-24 01:00:00', 1, 1),
                                                                                                                                                                                  (3, '4MUx705ptHnHnFuvfnV05MP82977oz/D23iNmnVleLvc70=', false, '1756053754275.jks', NULL, '1756053754275', 'END_ENTITY', '2025-08-24 02:00:00', '2026-03-24 01:00:00', 2, 1),
                                                                                                                                                                                  (4, 'QQXqobfoWq5gR1fG46SypFH2dyj/U0kR6G9rgTKD/k=', false, '1756053849726.jks', NULL, '1756053849726', 'INTERMEDIATE', '2025-08-24 02:00:00', '2026-03-24 01:00:00', 2, 1),
                                                                                                                                                                                  (5, 'sRmSYGCmT7+8U6xL70ZQpBSplfHEJOhLmvzSPrRIw=', false, '1756053912265.jks', NULL, '1756053912265', 'INTERMEDIATE', '2025-08-24 02:00:00', '2026-01-24 01:00:00', 4, 1)
    ON CONFLICT (id) DO NOTHING;
SELECT setval('users_id_seq', (SELECT MAX(id) FROM users), true);
SELECT setval('certificates_id_seq', (SELECT MAX(id) FROM certificates), true);

