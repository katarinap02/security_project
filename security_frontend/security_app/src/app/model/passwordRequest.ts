interface PasswordRequestDTO {
  siteName: string;
  username: string;
  encryptedPassword: string; // AES šifrovano
  encryptedAesKey: string;   // RSA šifrovani AES ključ
  iv: string;                // IV za AES-GCM
}