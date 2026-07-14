# 🔐 Public Key Infrastructure (PKI) & Shared Password Manager

A secure, enterprise-grade distributed system featuring a complete **Public Key Infrastructure (PKI)** for digital certificate lifecycle management, integrated with a end-to-end encrypted **Shared Password Manager**. 

The system is built using a robust **Java** backend (developed in IntelliJ IDEA) and an **Angular** frontend, enforcing strict security protocols including Multi-Factor Authentication (MFA), and comprehensive security auditing.

---

## 🏗️ System Architecture & Features

### 1. Public Key Infrastructure (PKI)
Provides centralized management of digital certificates across multiple user roles (Administrator, CA User, End-Entity User):
*   **Certificate Lifecycle:** Supports issuing, viewing, and revoking certificates across all levels:
    *   *Root (Self-Signed)*
    *   *Intermediate* (supports chains of arbitrary depth)
    *   *End-Entity (EE)*
*   **CSR Processing (X.509):** End-entity users can generate key pairs locally (e.g., via OpenSSL) and upload Certificate Signing Requests (`.pem` format) to be signed by authorized CAs.
*   **Secure Storage:** CA private keys and certificate chains are stored in password-protected keystores. Keystore passwords are encrypted using strong cryptographic algorithms (PBKDF2/AES) with unique symmetric keys per CA user.
*   **Certificate Revocation:** Real-time certificate status validation using CRL (Certificate Revocation List) distribution points or OCSP (Online Certificate Status Protocol).
*   **Smart Policy Templates:** Simplifies certificate creation for CA users by auto-filling extensions (Key Usage, Extended Key Usage, TTL) and enforcing validation policies using Regular Expressions (Regex) for Common Name (CN) and Subject Alternative Names (SANs).

### 2. End-to-End Encrypted Shared Password Manager
A zero-knowledge password vault available exclusively to End-Entity (EE) users utilizing asymmetric cryptography:
*   **Zero-Knowledge Decryption:** Sensitive passwords are encrypted using the user's public key on the frontend before being saved to the database.
*   **Web Crypto API:** Decryption is performed entirely client-side. The user's private key is never transmitted or stored on the server.
*   **Secure Sharing Model:** Users can securely share passwords. The frontend decrypts the password locally, re-encrypts it using the recipient's public key, and sends the newly encrypted payload back to the server.

---

## 🔒 Security & Defensive Controls

*   **Multi-Factor Authentication (MFA/2FA):** Secure login flow enhanced with an Authenticator Mobile App (TOTP) and Google reCAPTCHA/Cloudflare integration to prevent brute-force attacks.
*   **Active Session Management:** Real-time JWT token tracking allowing users to monitor active devices (IP address, browser, device type) and instantly revoke active sessions.
*   **Defense Against OWASP Top 10:**
    *   Strict input validation and sanitization to prevent **Cross-Site Scripting (XSS)**.
    *   Parameterized queries (Prepared Statements via Hibernate/JPA) protecting against **SQL Injection**.
    *   Context-aware HTML escaping on the Angular frontend.
*   **Security Auditing & Logging:** Immutable, structured logging mechanism documenting every security-relevant event (log rotation enabled, ensuring non-repudiation).
*   **Secure Communication:** End-to-end communication forced over HTTPS using a custom certificate issued directly by our PKI system.

---

## 🛠️ Tech Stack

*   **Backend:** Java, Hibernate/JPA, BouncyCastle (for cryptographic operations)
*   **Frontend:** Angular, RxJS, Web Crypto API
*   **Database:** PostgreSQL
*   **Identity Provider (Optional Integration):** Keycloak
*   **Static Code Analysis:** SonarQube / Snyk / Codacy

---

### 👥 Authors & Team
Developed as a collaborative project for the **Security in Electronic Business Systems** course (Faculty of Technical Sciences, Novi Sad):
*   **Katarina Petrović**
*   **Marija Mandić**
*   **Tanja Rizović**
