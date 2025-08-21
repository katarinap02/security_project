package com.pki.example.model;




import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "certificates")
@Getter
@Setter
public class Certificate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(unique = true, nullable = false)
    private String serialNumber;

    @Column(nullable = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date validFrom;

    @Column(nullable = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date validTo;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateType type;

    //koji drugi sertifikat je potpisao ovaj sertifikat
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_id")
    private Certificate issuer;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    // da li je validan sertifikat i zasto je povucen
    private boolean isRevoked = false;
    private String revocationReason;

    //fajl i enkriptovana lozinka za taj fajl
    @Column(nullable = false)
    private String keystoreFileName;

    @Setter
    @Column(nullable = false)
    private String encryptedKeystorePassword;

    public Certificate() {}

    public Certificate(Integer id, String serialNumber, Date validFrom, Date validTo, CertificateType type, String keystoreFileName, String encryptedKeystorePassword) {
        this.id = id;
        this.serialNumber = serialNumber;
        this.validFrom = validFrom;
        this.validTo = validTo;
        this.type = type;
        this.keystoreFileName = keystoreFileName;
        this.encryptedKeystorePassword = encryptedKeystorePassword;
    }


}
