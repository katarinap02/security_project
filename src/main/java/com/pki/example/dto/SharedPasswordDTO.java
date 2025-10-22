package com.pki.example.dto;

import com.pki.example.model.PasswordShare;

public class SharedPasswordDTO {
    private Long id;
    private Long passwordEntryId;
    private String encryptedAesKey;
    private String createdBy;
    private String siteName;
    private String username;
    private String encryptedPassword;
    private String iv;

    // Constructors, getters, setters
    public SharedPasswordDTO(PasswordShare share) {
        this.id = share.getId();
        this.passwordEntryId = share.getPasswordEntry().getId();
        this.encryptedAesKey = share.getEncryptedAesKey();
        this.createdBy = share.getCreatedBy();
        this.siteName = share.getPasswordEntry().getSiteName();
        this.username = share.getPasswordEntry().getUsername();
        this.encryptedPassword = share.getPasswordEntry().getEncryptedPassword();
        this.iv = share.getIv(); // ovo ostaje iz PasswordShare
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getPasswordEntryId() {
        return passwordEntryId;
    }

    public void setPasswordEntryId(Long passwordEntryId) {
        this.passwordEntryId = passwordEntryId;
    }

    public String getEncryptedAesKey() {
        return encryptedAesKey;
    }

    public void setEncryptedAesKey(String encryptedAesKey) {
        this.encryptedAesKey = encryptedAesKey;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public String getSiteName() {
        return siteName;
    }

    public void setSiteName(String siteName) {
        this.siteName = siteName;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public void setEncryptedPassword(String encryptedPassword) {
        this.encryptedPassword = encryptedPassword;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }
}
