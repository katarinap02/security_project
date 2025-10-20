package com.pki.example.dto;

import com.pki.example.model.CA;
import com.pki.example.model.CSR;
import com.pki.example.model.CSRStatus;

import java.time.LocalDateTime;

public class CSRDTO {
    private Long id;
    private Integer userId;
    private Long caId;
    private String subject;
    private byte[] publicKey;
    private Integer requestedValidityDays;
    private CSRStatus status;
    private LocalDateTime createdAt;


    public CSRDTO(Long id, Integer userId, Long caId, String subject, byte[] publicKey, Integer requestedValidityDays, CSRStatus status, LocalDateTime createdAt) {
        this.id = id;
        this.userId = userId;
        this.caId = caId;
        this.subject = subject;
        this.publicKey = publicKey;
        this.requestedValidityDays = requestedValidityDays;
        this.status = status;
        this.createdAt = createdAt;
    }


    public CSRDTO(CSR csr){
        this.id = csr.getId();
        this.userId = csr.getUser() != null ? csr.getUser().getId() : null;
        this.caId = csr.getCa() != null ? csr.getCa().getId() : null;
        this.subject = csr.getSubject();
        this.publicKey = csr.getPublicKey();
        this.requestedValidityDays = csr.getRequestedValidityDays();
        this.status = csr.getStatus();
        this.createdAt = csr.getCreatedAt();
    }


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Integer getUserId() {
        return userId;
    }

    public void setUserId(Integer userId) {
        this.userId = userId;
    }

    public Long getCaId() {
        return caId;
    }

    public void setCaId(Long caId) {
        this.caId = caId;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public Integer getRequestedValidityDays() {
        return requestedValidityDays;
    }

    public void setRequestedValidityDays(Integer requestedValidityDays) {
        this.requestedValidityDays = requestedValidityDays;
    }

    public CSRStatus getStatus() {
        return status;
    }

    public void setStatus(CSRStatus status) {
        this.status = status;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
