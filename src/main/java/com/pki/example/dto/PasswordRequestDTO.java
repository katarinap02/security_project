package com.pki.example.dto;

public class PasswordRequestDTO {

    private String siteName;
    private String username;

    private String encryptedPassword; // AES šifrovana lozinka
    private String encryptedAesKey;   // RSA šifrovani AES ključ
    private String iv;                // IV za AES-GCM

    public String getSiteName() { return siteName; }
    public void setSiteName(String siteName) { this.siteName = siteName; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getEncryptedPassword() { return encryptedPassword; }
    public void setEncryptedPassword(String encryptedPassword) { this.encryptedPassword = encryptedPassword; }

    public String getEncryptedAesKey() { return encryptedAesKey; }
    public void setEncryptedAesKey(String encryptedAesKey) { this.encryptedAesKey = encryptedAesKey; }

    public String getIv() { return iv; }
    public void setIv(String iv) { this.iv = iv; }
}
