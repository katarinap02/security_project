package com.pki.example.model;

import javax.persistence.*;
import java.util.List;

@Entity
public class CA {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private int maxCertificateDuration;

    @Lob
    private byte[] certificateBytes;
    @Lob
    private byte[] privateKeyBytes;
    @OneToMany(mappedBy = "ca")
    private List<CSR> signedCSRs;


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getMaxCertificateDuration() {
        return maxCertificateDuration;
    }

    public void setMaxCertificateDuration(int maxCertificateDuration) {
        this.maxCertificateDuration = maxCertificateDuration;
    }

    public byte[] getCertificateBytes() {
        return certificateBytes;
    }

    public void setCertificateBytes(byte[] certificateBytes) {
        this.certificateBytes = certificateBytes;
    }

    public byte[] getPrivateKeyBytes() {
        return privateKeyBytes;
    }

    public void setPrivateKeyBytes(byte[] privateKeyBytes) {
        this.privateKeyBytes = privateKeyBytes;
    }

    public List<CSR> getSignedCSRs() {
        return signedCSRs;
    }

    public void setSignedCSRs(List<CSR> signedCSRs) {
        this.signedCSRs = signedCSRs;
    }
}
