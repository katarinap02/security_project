package com.pki.example.model;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name="csr")
public class CSR {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ca_id", nullable = false)
    private CA ca;

    @Lob
    @Column(nullable = false, columnDefinition = "TEXT")
    private String subject;

    @Lob
    @Column(nullable = false)
    private String csrPem;

    @Lob
    @Column(nullable = false)
    private byte[] publicKey;

    private Integer requestedValidityDays;

    @Enumerated(EnumType.STRING)
    private CSRStatus status = CSRStatus.PENDING;

    private LocalDateTime createdAt = LocalDateTime.now();

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public CA getCa() {
        return ca;
    }

    public void setCa(CA ca) {
        this.ca = ca;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
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

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public String getCsrPem() {
        return csrPem;
    }

    public void setCsrPem(String csrPem) {
        this.csrPem = csrPem;
    }
}
