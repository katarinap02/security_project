package com.pki.example.dto;

public class PasswordShareRequestDTO {
    private Long passwordEntryId;
    private Long targetUserId;
    private String encryptedAesKey;
    private String iv;

    public Long getPasswordEntryId() {
        return passwordEntryId;
    }

    public void setPasswordEntryId(Long passwordEntryId) {
        this.passwordEntryId = passwordEntryId;
    }

    public Long getTargetUserId() {
        return targetUserId;
    }

    public void setTargetUserId(Long targetUserId) {
        this.targetUserId = targetUserId;
    }

    public String getEncryptedAesKey() {
        return encryptedAesKey;
    }

    public void setEncryptedAesKey(String encryptedAesKey) {
        this.encryptedAesKey = encryptedAesKey;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }
}

